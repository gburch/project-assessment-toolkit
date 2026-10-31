import io.shiftleft.semanticcpg.language.*
import io.shiftleft.codepropertygraph.generated.nodes.*
import scala.collection.mutable
import scala.util.control.NonFatal
import java.nio.charset.StandardCharsets.UTF_8
import java.nio.file.{Files, Paths}
import ujson.{Arr, Bool, Null, Num, Obj, Str, Value}

// Fixed, trusted query for captured source CPGs. No target code or dataflow runs.
@main def exec(cpgFile: String, out: String): Unit = {
  val errors = Arr()
  val gaps = Arr()
  val caveats = Arr(
    "Graph facts depend on the selected frontend; absent references or call targets are not proof of dead code.",
    "Unread bindings are review leads only; preserve initializer effects and callback, override and public signature contracts.",
    "No dataflow, reachability/dead-method inference or target-code execution is performed."
  )
  val result = Obj("schema_version" -> 1, "query_version" -> "1", "dataflow" -> "not_run",
    "errors" -> errors, "gaps" -> gaps, "caveats" -> caveats)
  var truncatedValues = 0L
  def text(value: String, limit: Int = 2048): String = {
    val safe = Option(value).getOrElse("")
    if (safe.length > limit) { truncatedValues += 1; safe.take(limit) } else safe
  }
  def line(value: Option[Int]): Value = value.filter(_ > 0).map(n => Num(n.toDouble)).getOrElse(Null)
  def identityRow(build: => Obj): Obj = {
    val before = truncatedValues
    val row = build
    row("identity_truncated") = Bool(truncatedValues != before)
    row
  }
  def attempt(name: String)(body: => Value): Unit = {
    try result(name) = body
    catch { case NonFatal(error) =>
      errors.value += Obj("section" -> name, "error" -> error.getClass.getName)
      result(name) = Obj("status" -> "error", "count" -> Null, "omitted" -> Null, "rows" -> Arr())
    }
  }
  // Keep a deterministic source-key prefix, bounded by BOTH rows and UTF-8 bytes.
  // Once a key is omitted, larger keys cannot backfill it depending on graph order.
  case class Row(key: String, value: Value, bytes: Int)
  class Bounded(val maxRows: Int, val maxBytes: Long) {
    private val retained = mutable.PriorityQueue.empty[Row](using Ordering.by[Row, String](_.key))
    private var cutoff: Option[String] = None
    private var bytes = 0L
    var count = 0L
    def add(row: Value): Unit = {
      count += 1
      val key = ujson.write(row)
      if (cutoff.forall(key < _)) {
        val size = key.getBytes(UTF_8).length + 1
        retained.enqueue(Row(key, row, size)); bytes += size
        while (retained.size > maxRows || bytes > maxBytes) {
          val removed = retained.dequeue(); bytes -= removed.bytes
          cutoff = Some(cutoff.fold(removed.key)(current => Ordering.String.min(current, removed.key)))
        }
      }
    }
    def output: Obj = {
      val rows = retained.iterator.toVector.sortBy(_.key).map(_.value)
      Obj("status" -> (if (count == rows.size) "complete" else "partial"),
        "count" -> Num(count.toDouble), "omitted" -> Num((count - rows.size).toDouble),
        "limit" -> maxRows, "byte_limit" -> Num(maxBytes.toDouble), "rows" -> Arr.from(rows))
    }
  }
  case class Flags(abstractMethod: Boolean, constructor: Boolean, body: Boolean)
  val flagCache = mutable.LongMap.empty[Flags]
  var languages = Set.empty[String]
  def flags(method: Method): Flags = flagCache.getOrElseUpdate(method.id, {
    val children = method.astChildren.toVector
    val abstractMethod = children.exists {
      case modifier: Modifier => modifier.modifierType == "ABSTRACT"
      case _ => false
    }
    val body = children.exists {
      case block: Block => block.astChildren.hasNext
      case _ => false
    }
    val constructor = Set("<init>", "<clinit>", "<fakeNew>").contains(method.name) ||
      (languages.exists(_.contains("PYTHON")) && Set("__init__", "__new__").contains(method.name)) ||
      (languages.exists(_.contains("SWIFT")) && method.name == "init") ||
      (languages.exists(language => language.contains("JAVASCRIPT") || language == "JSSRC") && method.name == "constructor")
    Flags(abstractMethod, constructor, body)
  })
  def methodRow(method: Method): Obj = identityRow {
    val state = flags(method)
    Obj("path" -> text(method.filename), "line" -> line(method.lineNumber),
      "end_line" -> line(method.lineNumberEnd), "name" -> text(method.name, 256),
      "full_name" -> text(method.fullName, 4096), "is_external" -> method.isExternal,
      "is_abstract" -> state.abstractMethod, "is_constructor" -> state.constructor, "has_body" -> state.body)
  }
  def assignmentLhsOnly(identifier: Identifier): Boolean = identifier.astParentOption.exists {
    case call: Call => call.name == "<operator>.assignment" && identifier.argumentIndex == 1
    case _ => false
  }
  try {
    importCpg(cpgFile, "captured-input", enhance = false).getOrElse(
      throw new IllegalArgumentException("Cannot load captured graph"))
    io.joern.x2cpg.X2Cpg.applyDefaultOverlays(cpg)
    console.applyPostProcessingPasses(cpg)
    languages = cpg.metaData.language.toSet
    result("metadata") = Obj("languages" -> Arr.from(languages.toVector.sorted),
      "language" -> languages.toVector.sorted.headOption.getOrElse("unknown"),
      "overlays" -> Arr.from(cpg.metaData.overlays.toVector.distinct.sorted),
      "cpg_versions" -> Arr.from(cpg.metaData.version.toVector.distinct.sorted),
      "max_heap_bytes" -> Num(Runtime.getRuntime.maxMemory.toDouble),
      "active_processors" -> Runtime.getRuntime.availableProcessors,
      "java_version" -> System.getProperty("java.version"))
    val edgeCounts = mutable.Map.empty[String, Long].withDefaultValue(0L)
    var edgeTotal = 0L
    cpg.graph.allEdges.foreach { edge =>
      edgeTotal += 1
      if (Set("CFG", "REF", "CALL", "CDG").contains(edge.label)) edgeCounts(edge.label) += 1
    }
    attempt("source_files") {
      val rows = new Bounded(4000, 256 * 1024)
      cpg.file.foreach(file => if (file.name != "<unknown>" && file.name != "<empty>")
        rows.add(identityRow { Obj("path" -> text(file.name)) }))
      rows.output
    }
    attempt("methods") {
      val rows = new Bounded(20000, 6 * 1024 * 1024)
      cpg.method.foreach(method => rows.add(methodRow(method)))
      rows.output
    }
    attempt("calls") {
      val rows = new Bounded(10000, 8 * 1024 * 1024)
      // Bound distinct source/target module pairs while counting all call facts.
      val pairs = mutable.Map.empty[(String, String), Long]
      val pairKeys = mutable.PriorityQueue.empty[(String, String)]
      var pairOverflow = false
      var internalOccurrences = 0L
      def moduleEdge(source: String, target: String): Unit = {
        internalOccurrences += 1
        val key = (source, target)
        if (source.length > 2048 || target.length > 2048) pairOverflow = true
        else if (pairs.contains(key)) pairs(key) += 1
        else if (pairs.size < 100000) { pairs(key) = 1L; pairKeys.enqueue(key) }
        else {
          pairOverflow = true
          if (Ordering.Tuple2[String, String].lt(key, pairKeys.head)) {
            pairs.remove(pairKeys.dequeue()); pairs(key) = 1L; pairKeys.enqueue(key)
          }
        }
      }
      var callNodes = 0L
      cpg.call.foreach { call =>
        callNodes += 1
        val caller = call.method
        val targets = NoResolve.getCalledMethods(call).iterator.buffered
        def callRow(target: Option[Method]): Obj = identityRow { Obj(
          "path" -> text(caller.filename), "line" -> line(call.lineNumber),
          "end_line" -> line(call.lineNumber), "name" -> text(call.name, 256),
          "caller_name" -> text(caller.name, 256), "caller_full_name" -> text(caller.fullName, 4096),
          "target_path" -> target.map(method => Str(text(method.filename))).getOrElse(Null),
          "target_line" -> target.map(method => line(method.lineNumber)).getOrElse(Null),
          "target_name" -> target.map(method => Str(text(method.name, 256))).getOrElse(Null),
          "target_full_name" -> target.map(method => Str(text(method.fullName, 4096))).getOrElse(Null),
          "resolution" -> target.map(method => if (method.isExternal) "external" else "internal").getOrElse("unresolved")) }
        if (!targets.hasNext) rows.add(callRow(None))
        else targets.foreach { target =>
          rows.add(callRow(Some(target)))
          if (!target.isExternal && !caller.isExternal && caller.filename.nonEmpty && target.filename.nonEmpty)
            moduleEdge(caller.filename, target.filename)
        }
      }
      val moduleRows = new Bounded(100000, 6 * 1024 * 1024)
      pairs.foreach { case ((source, target), count) =>
        moduleRows.add(Obj("source" -> source, "target" -> target, "count" -> Num(count.toDouble)))
      }
      val modules = moduleRows.output
      modules("count_is_lower_bound") = Bool(pairOverflow)
      if (pairOverflow) { modules("status") = Str("partial"); modules("omitted") = Null }
      modules("occurrences") = Num(internalOccurrences.toDouble)
      modules("omitted_occurrences") = Num((internalOccurrences -
        modules("rows").arr.iterator.map(_("count").num.toLong).sum).toDouble)
      modules("basis") = Str("Resolved internal CALL targets aggregated by source file; not import dependencies, runtime coverage or complete dynamic dispatch.")
      result("module_edges") = modules
      result("metrics") = Obj("nodes" -> cpg.graph.nodeCount, "edges" -> Num(edgeTotal.toDouble),
        "methods" -> cpg.method.size, "calls" -> Num(callNodes.toDouble),
        "edge_counts" -> Obj.from(Seq("CFG", "REF", "CALL", "CDG").map(label => label -> Num(edgeCounts(label).toDouble))))
      val output = rows.output
      output("basis") = Str("Stored CALL targets, including external stubs; missing targets are explicitly unresolved.")
      output
    }
    attempt("unread_bindings") {
      if (edgeCounts("REF") == 0) {
        Obj("status" -> "unsupported", "count" -> Null, "omitted" -> Null, "rows" -> Arr(),
          "reason" -> "No REF edges are available; unread-binding inference is unsupported.")
      } else {
        val references = mutable.LongMap.empty[(Int, Int)]
        cpg.identifier.foreach { identifier =>
          val read = !assignmentLhsOnly(identifier)
          identifier.refsTo.foreach { declaration => declaration match {
            case _: Local | _: MethodParameterIn =>
              val (refs, reads) = references.getOrElse(declaration.id, (0, 0))
              references(declaration.id) = (refs + 1, reads + (if (read) 1 else 0))
            case _ => ()
          }}
        }
        val rows = new Bounded(20000, 6 * 1024 * 1024)
        def binding(path: String, at: Option[Int], name: String, kind: String, id: Long, method: Method): Unit = {
          val (refs, reads) = references.getOrElse(id, (0, 0))
          if (reads == 0) {
            val state = flags(method)
            rows.add(identityRow { Obj("path" -> text(path), "line" -> line(at), "end_line" -> line(at),
              "symbol" -> text(name, 256), "binding_kind" -> kind,
              "method_name" -> text(method.name, 256), "method_full_name" -> text(method.fullName, 4096),
              "is_abstract" -> state.abstractMethod, "is_constructor" -> state.constructor, "has_body" -> state.body,
              "reference_count" -> refs, "read_count" -> reads) })
          }
        }
        cpg.local.foreach { local =>
          if (local.lineNumber.nonEmpty && references.getOrElse(local.id, (0, 0))._2 == 0)
            local.method.find(method => !method.isExternal &&
              !Set("<module>", "<body>", "<global>", "<program>", ":program").contains(method.name)).foreach { method =>
              binding(method.filename, local.lineNumber, local.name, "local", local.id, method)
            }
        }
        cpg.parameter.foreach { parameter =>
          if (parameter.index > 0 && parameter.lineNumber.nonEmpty &&
            !Set("this", "self", "cls").contains(parameter.name) &&
            !parameter.method.isExternal && parameter.method.name != "<fakeNew>")
            binding(parameter.method.filename, parameter.lineNumber, parameter.name, "parameter", parameter.id, parameter.method)
        }
        val output = rows.output
        output("basis") = Str("Identifier REF targets excluding only direct plain-assignment left operands; compound assignment counts as a read.")
        output("change_safety") = Str("unverified")
        output
      }
    }
  } catch { case NonFatal(error) =>
    errors.value += Obj("section" -> "load_or_overlays", "error" -> error.getClass.getName)
  } finally {
    result("truncated_values") = Num(truncatedValues.toDouble)
    if (truncatedValues > 0) gaps.value += Str("Overlong source-derived names or paths were truncated; identity checks may reject those rows.")
    val incompleteSections = Seq("source_files", "methods", "calls", "module_edges", "unread_bindings").filter { name =>
      result.obj.get(name).exists(value => value.obj.get("status").exists(_.str != "complete"))
    }
    incompleteSections.foreach(name => gaps.value += Str(s"$name is incomplete or unsupported; inspect its status and omission counts."))
    val partial = errors.value.nonEmpty || truncatedValues > 0 || incompleteSections.nonEmpty
    result("status") = Str(if (partial) "partial" else "complete")
    Files.writeString(Paths.get(out), ujson.write(result))
  }
}
