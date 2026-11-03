import io.shiftleft.semanticcpg.language.*
import io.shiftleft.semanticcpg.utils.MemberAccess.isFieldAccess
import io.shiftleft.codepropertygraph.generated.DiffGraphBuilder
import io.shiftleft.codepropertygraph.generated.nodes.*
import io.joern.dataflowengineoss.language.*
import io.joern.dataflowengineoss.queryengine.{Engine, EngineContext, EngineConfig}
import io.joern.dataflowengineoss.layers.dataflows.{OssDataFlow, OssDataFlowOptions}
import io.joern.dataflowengineoss.passes.reachingdef.{DataFlowSolver, DdgGenerator, ReachingDefPass, ReachingDefProblem, ReachingDefTransferFunction}
import io.shiftleft.semanticcpg.layers.LayerCreatorContext
import scala.collection.mutable
import scala.util.control.NonFatal
import java.nio.charset.StandardCharsets.UTF_8
import java.nio.file.{Files, Paths}
import java.util.concurrent.atomic.{AtomicBoolean, AtomicLong}
import ujson.{Arr, Bool, Null, Num, Obj, Str, Value}

// Exact optimized-gen cardinality for pinned Joern 4.0.669. Count node IDs,
// without constructing its reaching-def flow graph, kill sets or solver state. Preserve
// call/argument traversal multiplicity for the producer's lone-name rule.
def optimizedDefinitionCount(method: Method): Long = {
  val params = method.parameter.toVector
  val domain = mutable.HashSet.empty[Long]
  domain += method.id
  domain += method.methodReturn.id
  params.foreach(node => domain += node.id)
  method.parameter.asOutput.foreach(node => domain += node.id)
  method.reversePostOrder.foreach(node => domain += node.id)
  method.cfgNode.foreach(node => domain += node.id)
  val calls = method.call.toVector
  val declaredNames = params.iterator.map(_.name).toSet ++ method.local.name.toSet
  val returnedNames = method._returnViaContainsOut.ast.isIdentifier.name.toSet
  val seenNames = mutable.HashSet.empty[String]
  val sole = mutable.HashMap.empty[String, (Long, Long)]
  calls.foreach { call =>
    call.argument.isIdentifier.foreach { arg =>
      if (!declaredNames(arg.name) && !returnedNames(arg.name)) {
        if (seenNames.add(arg.name)) sole(arg.name) = (call.id, arg.id)
        else sole.remove(arg.name)
      }
    }
  }
  val loneByCall = sole.values.toVector.groupMap(_._1)(_._2).view.mapValues(_.toSet).toMap
  val genCounts = mutable.HashMap.empty[Long, Int]
  calls.filterNot(call => isFieldAccess(call.name)).foreach { call =>
    val defs = mutable.HashSet.empty[Long]
    if (domain(call.id)) defs += call.id
    call.argument.foreach {
      case node: Call if domain(node.id) => defs += node.id
      case node: Identifier if domain(node.id) => defs += node.id
      case _ => ()
    }
    loneByCall.get(call.id).foreach(ids => defs --= ids)
    genCounts(call.id) = defs.size
  }
  params.iterator.map(_.id).toSet.size.toLong + genCounts.valuesIterator.map(_.toLong).sum
}

// Valid only at an initial endpoint after the reaching-def overlay is complete.
// These excluded starters can expand across calls without an incoming DDG edge.
def provenEmptyStarter(sink: CfgNode): Boolean = sink match {
  case _: MethodParameterIn | _: Call | _: MethodRef => false
  case _ => !sink.inE("REACHING_DEF").exists { edge => edge.src match {
    case node: CfgNode => !node.isInstanceOf[Method]
    case _ => false
  }}
}

// Fixed, trusted query for captured source CPGs. Deep adds modeled dataflow, never target execution.
@main def exec(cpgFile: String, out: String, profile: String = "standard",
    runToken: String = "", flowSeconds: Int = 1200): Unit = {
  require(Set("standard", "deep")(profile), "Unsupported analysis profile")
  val deep = profile == "deep"
  require((runToken.isEmpty && !deep) || runToken.matches("[0-9a-f]{32}"), "Invalid run token")
  require(flowSeconds >= 1 && flowSeconds <= 86400, "Invalid flow work budget")
  val errors = Arr()
  val gaps = Arr()
  val caveats = Arr(
    "Graph facts depend on the selected frontend; absent references or call targets are not proof of dead code.",
    "Unread bindings are review leads only; preserve initializer effects and callback, override and public signature contracts.",
    "Deep dataflow describes modeled parameter influence, not external taint, feasible execution, dead-method proof or target-code execution."
  )
  val result = Obj("schema_version" -> 1, "query_version" -> "8", "run_token" -> runToken, "dataflow" -> "not_run",
    "errors" -> errors, "gaps" -> gaps, "caveats" -> caveats)
  def writeResult(value: Value, name: String = out): Unit = {
    val destination = Paths.get(name)
    val temporary = Files.createTempFile(destination.toAbsolutePath.getParent, ".pat-query-", ".json")
    try {
      Files.writeString(temporary, ujson.write(value))
      Files.move(temporary, destination, java.nio.file.StandardCopyOption.REPLACE_EXISTING,
        java.nio.file.StandardCopyOption.ATOMIC_MOVE)
    } finally Files.deleteIfExists(temporary)
  }
  val began = System.nanoTime()
  val phases = Arr()
  def phase(name: String): Unit = {
    // Aggregate timings only: no source names, paths, code or error messages.
    phases.value += Obj("phase" -> name,
      "elapsed_seconds" -> Num((System.nanoTime() - began).toDouble / 1e9))
    writeResult(Obj("schema_version" -> 1, "query_version" -> "8", "phases" -> phases), out + ".phases.json")
  }
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
    def add(row: Value): Unit = addKey(ujson.write(row))(row)
    def addKey(key: String)(build: => Value): Unit = {
      count += 1
      if (cutoff.forall(key < _)) {
        val row = build
        val size = ujson.write(row).getBytes(UTF_8).length + 1
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
  // Max-min file quotas keep a large early file from consuming every row.
  // Only bounded method references are retained; JSON is built during output.
  // Round-robin byte admission is deterministic and skips a row that cannot fit.
  class FairRows[A](counts: Map[String, Long], maxRows: Int, maxBytes: Long, metadataBytes: Long) {
    case class Choice(key: String, value: A)
    private val paths = counts.keys.toVector.sorted
    private val caps = mutable.Map.from(paths.map(_ -> 0))
    private val retained = mutable.Map.empty[String, mutable.PriorityQueue[Choice]]
    private var remaining = maxRows
    private var active = paths
    while (remaining > 0 && active.nonEmpty) {
      val share = math.max(remaining / active.size, 1)
      active.foreach { path =>
        val take = math.min(math.min(counts(path) - caps(path), share.toLong), remaining.toLong).toInt
        caps(path) += take; remaining -= take
      }
      active = active.filter(path => caps(path) < counts(path))
    }
    def add(path: String, key: String)(value: => A): Unit = if (caps(path) > 0) {
      val rows = retained.getOrElseUpdate(path,
        mutable.PriorityQueue.empty[Choice](using Ordering.by[Choice, String](_.key)))
      if (rows.size < caps(path)) rows.enqueue(Choice(key, value))
      else if (key < rows.head.key) { rows.dequeue(); rows.enqueue(Choice(key, value)) }
    }
    def output(build: A => Value): Obj = {
      val choices = retained.view.mapValues(_.iterator.toVector.sortBy(_.key)).toMap
      val rows = Arr()
      val accepted = mutable.Map.empty[String, Int].withDefaultValue(0)
      val rowByteLimit = maxBytes - metadataBytes - 4096
      var bytes = 0L
      var byteOmissions = 0L
      var rank = 0
      var active = paths.filter(path => choices.get(path).exists(_.nonEmpty))
      while (active.nonEmpty) {
        active.foreach { path =>
          val row = build(choices(path)(rank).value)
          val size = ujson.write(row).getBytes(UTF_8).length + 1
          if (bytes + size <= rowByteLimit) {
            rows.value += row; bytes += size; accepted(path) += 1
          } else byteOmissions += 1
        }
        rank += 1
        active = active.filter(path => choices(path).size > rank)
      }
      val files = new Bounded(paths.size, metadataBytes)
      paths.foreach(path => files.add(identityRow {
        Obj("path" -> text(path), "count" -> Num(counts(path).toDouble), "retained" -> accepted(path))
      }))
      val count = counts.valuesIterator.sum
      val represented = accepted.count(_._2 > 0)
      Obj("status" -> (if (count == rows.value.size) "complete" else "partial"),
        "count" -> Num(count.toDouble), "omitted" -> Num((count - rows.value.size).toDouble),
        "limit" -> maxRows, "byte_limit" -> Num(maxBytes.toDouble), "rows" -> rows,
        "sampling" -> "max_min_per_file_then_round_robin",
        "source_files" -> paths.size, "retained_files" -> represented,
        "omitted_files" -> (paths.size - represented), "row_byte_limit" -> Num(rowByteLimit.toDouble),
        "byte_omissions" -> Num(byteOmissions.toDouble), "file_coverage" -> files.output)
    }
  }
  val samplingDigest = java.security.MessageDigest.getInstance("SHA-256")
  val samplingHex = java.util.HexFormat.of()
  def methodSamplingKey(root: String, path: String, start: Int, end: Int,
      name: String, fullName: String, abstractMethod: Boolean, constructor: Boolean, body: Boolean): String = {
    def relative(value: String): String = value.replace('\\', '/').replace(root.replace('\\', '/') + "/", "")
    val file = relative(path)
    val qualified = if (file.nonEmpty) relative(fullName).replace(file, "<file>") else relative(fullName)
    val identity = Seq(f"$start%010d", f"$end%010d", name.take(257), qualified.take(4097),
      abstractMethod.toString, constructor.toString, body.toString).mkString("\u0000")
    samplingHex.formatHex(samplingDigest.digest(identity.getBytes(UTF_8))) + "\u0000" + identity
  }
  // Separate supported dependencies from broader producer target hypotheses,
  // sharing the previous aggregate byte budget between the two views.
  class ModulePairs(val basis: String) {
    private val pairs = mutable.Map.empty[(String, String), Long]
    private val keys = mutable.PriorityQueue.empty[(String, String)]
    private var overflow = false
    private var occurrences = 0L
    def add(source: String, target: String): Unit = {
      occurrences += 1
      val key = (source, target)
      if (source.length > 2048 || target.length > 2048) overflow = true
      else if (pairs.contains(key)) pairs(key) += 1
      else if (pairs.size < 100000) { pairs(key) = 1L; keys.enqueue(key) }
      else {
        overflow = true
        if (Ordering.Tuple2[String, String].lt(key, keys.head)) {
          pairs.remove(keys.dequeue()); pairs(key) = 1L; keys.enqueue(key)
        }
      }
    }
    def output: Obj = {
      val rows = new Bounded(100000, 3 * 1024 * 1024)
      pairs.foreach { case ((source, target), count) =>
        rows.add(Obj("source" -> source, "target" -> target, "count" -> Num(count.toDouble)))
      }
      val result = rows.output
      result("count_is_lower_bound") = Bool(overflow)
      if (overflow) { result("status") = Str("partial"); result("omitted") = Null }
      result("occurrences") = Num(occurrences.toDouble)
      result("omitted_occurrences") = Num((occurrences -
        result("rows").arr.iterator.map(_("count").num.toLong).sum).toDouble)
      result("basis") = Str(basis)
      result
    }
  }
  case class Flags(abstractMethod: Boolean, constructor: Boolean, body: Boolean)
  val flagCache = mutable.LongMap.empty[Flags]
  val contractOwners = mutable.Set.empty[String]
  var languages = Set.empty[String]
  def ancestors(node: AstNode): Iterator[AstNode] =
    Iterator.iterate(node.astParentOption)(_.flatMap(_.astParentOption))
      .take(64).takeWhile(_.nonEmpty).flatten
  def flags(method: Method): Flags = flagCache.getOrElseUpdate(method.id, {
    val children = method.astChildren.toVector
    val abstractMethod = children.exists {
      case modifier: Modifier => modifier.modifierType == "ABSTRACT"
      case _ => false
    } || ancestors(method).exists {
      case owner: Method => contractOwners(owner.fullName)
      case owner: TypeDecl => contractOwners(owner.fullName)
      case _ => false
    }
    val body = children.exists {
      case block: Block => block.astChildren.exists {
        case _: Literal => false // Standalone docstrings/ellipsis are not an implementation.
        case call: Call if call.name == "<operator>.pass" => false
        case _ => true
      }
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
    phase("import_started")
    importCpg(cpgFile, "captured-input", enhance = false).getOrElse(
      throw new IllegalArgumentException("Cannot load captured graph"))
    phase("import_completed")
    phase("default_overlays_started")
    io.joern.x2cpg.X2Cpg.applyDefaultOverlays(cpg)
    phase("default_overlays_completed")
    phase("postprocessing_started")
    console.applyPostProcessingPasses(cpg)
    phase("postprocessing_completed")
    phase("base_evidence_started")
    languages = cpg.metaData.language.toSet
    result("metadata") = Obj("languages" -> Arr.from(languages.toVector.sorted),
      "language" -> languages.toVector.sorted.headOption.getOrElse("unknown"),
      "overlays" -> Arr.from(cpg.metaData.overlays.toVector.distinct.sorted),
      "cpg_versions" -> Arr.from(cpg.metaData.version.toVector.distinct.sorted),
      "max_heap_bytes" -> Num(Runtime.getRuntime.maxMemory.toDouble),
      "active_processors" -> Runtime.getRuntime.availableProcessors,
      "java_version" -> System.getProperty("java.version"))
    val capturedDeclarations = mutable.Set.empty[Long]
    val captureOrigins = mutable.Map.empty[String, Declaration]
    val edgeCounts = mutable.Map.empty[String, Long].withDefaultValue(0L)
    var edgeTotal = 0L
    cpg.graph.allEdges.foreach { edge =>
      edgeTotal += 1
      if (Set("CFG", "REF", "CALL", "CDG").contains(edge.label)) edgeCounts(edge.label) += 1
      if (edge.label == "REF") edge.src match {
        case binding: ClosureBinding => edge.dst match {
          case declaration: Declaration =>
            capturedDeclarations += declaration.id
            Option(binding.propertiesMap.get("CLOSURE_BINDING_ID")).foreach(value =>
              captureOrigins(value.toString) = declaration)
          case _ => ()
        }
        case _ => ()
      }
    }
    attempt("source_files") {
      val rows = new Bounded(if (deep) 20000 else 4000, if (deep) 2 * 1024 * 1024 else 256 * 1024)
      cpg.file.foreach(file => if (file.name != "<unknown>" && file.name != "<empty>")
        rows.add(identityRow { Obj("path" -> text(file.name)) }))
      rows.output
    }
    val sourceFiles = cpg.file.name.filter(name => name.nonEmpty &&
      name != "<unknown>" && name != "<empty>").toSet
    def locatedSource(method: Method): Boolean = !method.isExternal &&
      method.lineNumber.exists(_ > 0) && sourceFiles.contains(method.filename)
    cpg.typeDecl.foreach { owner =>
      if (owner.inheritsFromTypeFullName.exists(name => name.endsWith(".Protocol") || name == "Protocol"))
        contractOwners += owner.fullName
    }
    val canonicalCache = mutable.LongMap.empty[Option[Declaration]]
    def canonical(declaration: Declaration): Option[Declaration] =
      canonicalCache.getOrElseUpdate(declaration.id, {
        var current = declaration
        val seen = mutable.Set.empty[Long]
        var answer: Option[Declaration] = None
        var finished = false
        while (!finished && seen.size < 32 && !seen(current.id)) {
          seen += current.id
          current match {
            case local: Local => Option(local.propertiesMap.get("CLOSURE_BINDING_ID")) match {
              case Some(key) => captureOrigins.get(key.toString) match {
                case Some(original) => current = original
                case None => finished = true
              }
              case None => answer = Some(current); finished = true
            }
            case _ => answer = Some(current); finished = true
          }
        }
        answer
      })
    val boundMethods = mutable.LongMap.empty[mutable.Set[String]]
    def bind(identifier: Identifier, fullName: String): Unit = identifier.refsTo.foreach { declaration =>
      canonical(declaration).foreach(original =>
        boundMethods.getOrElseUpdate(original.id, mutable.Set.empty[String]) += fullName)
    }
    cpg.methodRef.foreach { reference => reference.astParentOption match {
      case Some(identifier: Identifier) => bind(identifier, reference.methodFullName)
      case Some(assignment: Call) if assignment.name == "<operator>.assignment" =>
        assignment.argument.filter(_.argumentIndex == 1).collect { case identifier: Identifier => identifier }
          .foreach(identifier => bind(identifier, reference.methodFullName))
      case _ => ()
    }}
    // Explicit source imports, resolved only against captured file identities.
    // A same-named parameter does not inherit the imported declaration's binding.
    val imports = mutable.Map.empty[(Long, String, Int), String]
    cpg.imports.foreach { entry =>
      val entity = Option(entry.propertiesMap.get("IMPORTED_ENTITY")).map(_.toString)
      val alias = Option(entry.propertiesMap.get("IMPORTED_AS")).map(_.toString)
      for (name <- alias; imported <- entity; at <- entry.lineNumber;
           owner <- ancestors(entry).collectFirst { case method: Method => method })
        imports((owner.id, name, at)) = imported
    }
    val importedBindings = mutable.LongMap.empty[String]
    cpg.local.foreach { local =>
      for (at <- local.lineNumber; owner <- local.method;
           entity <- imports.get((owner.id, local.name, at))) importedBindings(local.id) = entity
    }
    def matchesImport(entity: String, caller: Method, target: Method): Boolean = {
      val split = entity.lastIndexOf(':')
      if (split < 0 || entity.substring(split + 1) != target.name) false
      else {
        val module = entity.substring(0, split)
        if (!module.startsWith("./") && !module.startsWith("../")) false
        else {
          val base = Option(Paths.get(caller.filename).getParent).getOrElse(Paths.get(""))
            .resolve(module).normalize.toString.replace('\\', '/')
          val alternatives = Set(base) ++ Seq(".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs")
            .flatMap(extension => Seq(base + extension, base + "/index" + extension))
          alternatives(target.filename)
        }
      }
    }
    def directCallee(identifier: Identifier, call: Call): Boolean =
      call.name == identifier.name && call.code.trim.matches(
        "(?s)" + java.util.regex.Pattern.quote(identifier.name) + "\\s*\\(.*")
    def calleeBindings(call: Call): Vector[Declaration] = call.astChildren
      .collect { case identifier: Identifier if directCallee(identifier, call) => identifier }
      .flatMap(_.refsTo).flatMap(canonical).toVector
    val directTargets = mutable.Set.empty[String]
    val escapedMethods = mutable.Set.empty[String]
    val crossFileMethods = mutable.Set.empty[Long]
    cpg.identifier.foreach { identifier =>
      if (!assignmentLhsOnly(identifier)) {
        val called = identifier.astParentOption.exists {
          case call: Call => directCallee(identifier, call)
          case _ => false
        }
        if (!called) identifier.refsTo.flatMap(canonical).foreach { original =>
          boundMethods.get(original.id).foreach(names => escapedMethods ++= names)
        }
      }
    }
    cpg.methodRef.foreach { reference => reference.astParentOption match {
      case Some(_: Identifier) => ()
      case Some(assignment: Call) if assignment.name == "<operator>.assignment" => ()
      case _ => escapedMethods += reference.methodFullName
    }}
    def qualification(call: Call, target: Method, bindings: Vector[Declaration], receiverTypes: Set[String]): (String, String, String) = {
      if (!locatedSource(target)) ("unresolved", "external_or_unlocated_target", "low")
      else {
        val binding = bindings.exists { declaration =>
          boundMethods.get(declaration.id).exists(_(target.fullName)) ||
            importedBindings.get(declaration.id).exists(matchesImport(_, call.method, target))
        }
        val receiver = target.astParentOption.exists {
          case owner: TypeDecl => receiverTypes(owner.fullName)
          case _ => false
        }
        if (binding) ("source_supported", "callee_REF_to_definition_or_explicit_import", "medium")
        else if (receiver) ("producer_inferred", "modeled_receiver_type_matches_owner_annotation_unverified", "low")
        else if (languages.exists(name => name == "JAVA" || name == "JAVASRC") &&
          call.dispatchType == "STATIC_DISPATCH" && call.methodFullName == target.fullName &&
          target.astChildren.exists { case modifier: Modifier => modifier.modifierType == "STATIC"; case _ => false })
          ("source_supported", "exact_static_dispatch_to_static_Java_declaration", "medium")
        else ("producer_inferred", "target_not_validated_by_callee_binding_or_receiver", "low")
      }
    }
    attempt("methods") {
      var external = 0L
      var unlocated = 0L
      val counts = mutable.Map.empty[String, Long].withDefaultValue(0L)
      cpg.method.foreach { method =>
        if (method.isExternal) external += 1
        else if (!locatedSource(method)) unlocated += 1
        else counts(method.filename) += 1
      }
      val rows = new FairRows[Method](counts.toMap, if (deep) 200000 else 20000,
        if (deep) 48 * 1024 * 1024 else 6 * 1024 * 1024,
        if (deep) 2 * 1024 * 1024 else 256 * 1024)
      // Adapter contract: captured source is beside cpg.bin in a source directory.
      // Remove this private root before hashing, even when filename is relative.
      val sourceRoot = Paths.get(cpgFile).toAbsolutePath.getParent.resolve("source").normalize.toString
      cpg.method.filter(locatedSource).foreach { method =>
        val state = flags(method)
        // Every output field participates in ties, including truncation boundaries;
        // graph IDs and traversal order never determine which source row survives.
        val key = methodSamplingKey(sourceRoot, method.filename, method.lineNumber.getOrElse(0),
          method.lineNumberEnd.getOrElse(0), method.name, method.fullName,
          state.abstractMethod, state.constructor, state.body)
        rows.add(method.filename, key)(method)
      }
      val output = rows.output(methodRow)
      output("external_models") = Num(external.toDouble)
      output("unlocated_models") = Num(unlocated.toDouble)
      output("basis") = Str("Located source methods receive max-min per-file row quotas, SHA-256-ranked source identities within each file, and deterministic round-robin byte admission. Private source roots and graph IDs do not affect ranking. External/unlocated models consume no quota; oversized rows do not block other files. Counts describe model coverage, not absence of source methods.")
      output
    }
    attempt("calls") {
      val rows = new Bounded(if (deep) 50000 else 10000, if (deep) 24 * 1024 * 1024 else 8 * 1024 * 1024)
      val supported = new ModulePairs("Source-supported call targets, validated by callee REF binding, explicit import or exact dispatch to a static Java declaration; not runtime coverage.")
      val inferred = new ModulePairs("Unvalidated producer CALL-target hypotheses; these are not established module dependencies or runtime calls.")
      val classifications = mutable.Map.empty[String, Long].withDefaultValue(0L)
      var callNodes = 0L
      cpg.call.foreach { call =>
        callNodes += 1
        val caller = call.method
        val bindings = calleeBindings(call)
        val receiverTypes = call.argument.filter(_.argumentIndex == 0).collect { case identifier: Identifier => identifier.typeFullName }
          .filterNot(value => value == "ANY" || value == "<unknown>").toSet
        val targets = NoResolve.getCalledMethods(call).iterator.buffered
        def callRow(target: Option[Method], status: String, basis: String, confidence: String): Obj = identityRow { Obj(
          "path" -> text(caller.filename), "line" -> line(call.lineNumber),
          "end_line" -> line(call.lineNumber), "name" -> text(call.name, 256),
          "caller_name" -> text(caller.name, 256), "caller_full_name" -> text(caller.fullName, 4096),
          "target_path" -> target.map(method => Str(text(method.filename))).getOrElse(Null),
          "target_line" -> target.map(method => line(method.lineNumber)).getOrElse(Null),
          "target_name" -> target.map(method => Str(text(method.name, 256))).getOrElse(Null),
          "target_full_name" -> target.map(method => Str(text(method.fullName, 4096))).getOrElse(Null),
          "resolution" -> target.map(method => if (method.isExternal) "external" else "internal").getOrElse("unresolved"),
          "dependency_status" -> status, "dependency_basis" -> basis, "confidence" -> confidence) }
        def retain(target: Option[Method], status: String, basis: String, confidence: String): Unit = {
          classifications(status) += 1
          val rank = if (status == "source_supported") "0" else if (status == "producer_inferred") "1" else "2"
          val key = Seq(rank, caller.filename, f"${call.lineNumber.getOrElse(0)}%010d",
            caller.fullName, call.name, target.map(_.fullName).getOrElse(""), target.map(_.filename).getOrElse("")).mkString("\u0000")
          rows.addKey(key)(callRow(target, status, basis, confidence))
        }
        if (!targets.hasNext) retain(None, "unresolved", "no_stored_target", "low")
        else targets.foreach { target =>
          val (status, basis, confidence) = qualification(call, target, bindings, receiverTypes)
          retain(Some(target), status, basis, confidence)
          if (locatedSource(caller) && locatedSource(target)) {
            if (status == "source_supported") {
              supported.add(caller.filename, target.filename)
              directTargets += target.fullName
              if (caller.filename != target.filename) {
                crossFileMethods += caller.id
                crossFileMethods += target.id
              }
            } else if (status == "producer_inferred") inferred.add(caller.filename, target.filename)
          }
        }
      }
      result("module_edges") = supported.output
      result("inferred_module_edges") = inferred.output
      result("metrics") = Obj("nodes" -> cpg.graph.nodeCount, "edges" -> Num(edgeTotal.toDouble),
        "methods" -> cpg.method.size, "calls" -> Num(callNodes.toDouble),
        "edge_counts" -> Obj.from(Seq("CFG", "REF", "CALL", "CDG").map(label => label -> Num(edgeCounts(label).toDouble))))
      val output = rows.output
      output("classifications") = Obj.from(classifications.toVector.sortBy(_._1).map((key, value) => key -> Num(value.toDouble)))
      output("basis") = Str("Source-supported targets are prioritized in the bounded sample. Producer inference remains separate; exact full names alone do not prove a dynamic callee's binding.")
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
        val suppressed = mutable.Map.empty[String, Long].withDefaultValue(0L)
        def privateMethod(method: Method): Boolean =
          (method.name.startsWith("_") && !method.name.startsWith("__")) ||
            method.astChildren.exists {
              case modifier: Modifier => modifier.modifierType == "PRIVATE"
              case _ => false
            }
        def binding(path: String, at: Option[Int], name: String, kind: String, id: Long, method: Method): Unit = {
          val (refs, reads) = references.getOrElse(id, (0, 0))
          if (reads == 0) {
            val state = flags(method)
            val reason =
              if (capturedDeclarations(id)) Some("captured_or_nonlocal_binding")
              else if (state.abstractMethod || !state.body || (kind == "parameter" && state.constructor)) Some("contract_or_bodyless_signature")
              else if (kind == "parameter" && escapedMethods(method.fullName)) Some("callback_or_escaping_signature")
              else if (kind == "parameter" && !privateMethod(method)) Some("public_or_override_signature_unknown")
              else if (kind == "parameter" && !directTargets(method.fullName)) Some("private_signature_without_supported_direct_call")
              else if (kind == "local" && boundMethods.contains(id)) Some("function_value_binding_not_dead_method_proof")
              else None
            reason match {
              case Some(value) => suppressed(value) += 1
              case None => rows.add(identityRow { Obj("path" -> text(path), "line" -> line(at), "end_line" -> line(at),
                "symbol" -> text(name, 256), "binding_kind" -> kind,
                "method_name" -> text(method.name, 256), "method_full_name" -> text(method.fullName, 4096),
                "is_abstract" -> state.abstractMethod, "is_constructor" -> state.constructor, "has_body" -> state.body,
                "reference_count" -> refs, "read_count" -> reads,
                "cleanup_status" -> "review_candidate", "capture_status" -> "not_captured",
                "signature_status" -> (if (kind == "parameter") "private_direct_only" else "not_applicable"),
                "basis" -> "identifier_REF_reads_with_capture_and_function_escape_checks") })
            }
          }
        }
        cpg.local.foreach { local =>
          if (local.lineNumber.nonEmpty && references.getOrElse(local.id, (0, 0))._2 == 0)
            local.method.find(method => !method.isExternal &&
              !Set("<module>", "<body>", "<global>", "<program>", ":program").contains(method.name)).foreach { method =>
              if (local.propertiesMap.containsKey("CLOSURE_BINDING_ID")) suppressed("captured_or_nonlocal_binding") += 1
              else binding(method.filename, local.lineNumber, local.name, "local", local.id, method)
            }
        }
        cpg.parameter.foreach { parameter =>
          if (parameter.index > 0 && parameter.lineNumber.nonEmpty &&
            !Set("this", "self", "cls").contains(parameter.name) &&
            !parameter.method.isExternal && parameter.method.name != "<fakeNew>")
            binding(parameter.method.filename, parameter.lineNumber, parameter.name, "parameter", parameter.id, parameter.method)
        }
        val output = rows.output
        output("suppressed") = Obj.from(suppressed.toVector.sortBy(_._1).map((key, value) => key -> Num(value.toDouble)))
        output("captured_declarations") = capturedDeclarations.size
        output("basis") = Str("Identifier REF reads with closure/nonlocal capture, function-value escape and signature checks. Public/callback/override signature changes remain unknown; compound assignment counts as a read.")
        output("change_safety") = Str("unverified")
        output
      }
    }
    phase("base_evidence_completed")
    if (deep) {
      // Preserve validated base facts if a later expensive flow pass is killed.
      // The adapter accepts this distinct checkpoint only with failed process
      // provenance; a normal final result never carries this marker.
      val checkpoint = ujson.read(ujson.write(result))
      checkpoint("checkpoint") = Str("base_before_dataflow")
      checkpoint("status") = Str("partial")
      checkpoint("dataflow") = Str("error")
      checkpoint("dataflow_analysis") = Obj("status" -> "error")
      checkpoint("errors").arr += Obj("section" -> "dataflow_analysis", "error" -> "InterruptedDataflow")
      // Keep a separate immutable base: finally may replace the primary output
      // with incomplete state even after a fatal JVM error and nonzero exit.
      writeResult(checkpoint, out + ".base.json")
      writeResult(checkpoint)
      val baseDigest = java.security.MessageDigest.getInstance("SHA-256")
      val baseStream = Files.newInputStream(Paths.get(out + ".base.json"))
      try {
        val buffer = new Array[Byte](65536)
        var count = baseStream.read(buffer)
        while (count >= 0) {
          if (count > 0) baseDigest.update(buffer, 0, count)
          count = baseStream.read(buffer)
        }
      } finally baseStream.close()
      val baseSha256 = java.util.HexFormat.of().formatHex(baseDigest.digest())
      // PAT_DATAFLOW_CHECKPOINT_COMPLETE
      val maxDefinitions = 50000
      val maxCallDepth = 8
      val stepLimit = 64
      val pathsPerSink = 64
      val dataflow = Obj("status" -> "error", "max_definitions" -> maxDefinitions,
        "max_call_depth" -> maxCallDepth, "maximum_definitions_observed" -> 0,
        "semantics" -> "joern_default",
        "scope" -> "method_parameters_to_returns_and_selected_operation_arguments",
        "methods_total" -> 0, "methods_analyzed" -> 0, "methods_skipped" -> 0,
        "skipped_methods" -> Obj("status" -> "complete", "count" -> 0, "omitted" -> 0, "rows" -> Arr()),
        "paths" -> Obj("status" -> "complete", "count" -> 0, "omitted" -> 0,
          "count_is_lower_bound" -> false, "rows" -> Arr()),
        "queries" -> Obj("sinks_total" -> 0, "sinks_queried" -> 0, "sinks_omitted" -> 0,
          "paths_truncated" -> 0, "step_limit" -> stepLimit))
      result("dataflow_analysis") = dataflow
      try {
        phase("definition_accounting_started")
        val methods = cpg.method.filter(locatedSource).toVector.sortBy(method =>
          (method.filename, method.lineNumber.getOrElse(0), method.fullName))
        dataflow("methods_total") = methods.size
        // The stock pass processes every graph method, including unlocated and
        // external ones. Keep that domain; source metadata below stays located.
        val definitionCounts = cpg.method.map(method => method.id -> optimizedDefinitionCount(method)).toMap
        val skippedIds = mutable.Set.empty[Long]
        val skipped = new Bounded(20000, 2 * 1024 * 1024)
        var maximumDefinitions = 0L
        methods.foreach { method =>
          val definitions = definitionCounts(method.id)
          maximumDefinitions = math.max(maximumDefinitions, definitions)
          if (definitions > maxDefinitions) {
            skippedIds += method.id
            skipped.add(identityRow { Obj("path" -> text(method.filename),
              "line" -> line(method.lineNumber), "method" -> text(method.fullName, 4096),
              "definitions" -> Num(definitions.toDouble), "reason" -> "definition_limit") })
          }
        }
        dataflow("maximum_definitions_observed") = Num(maximumDefinitions.toDouble)
        dataflow("methods_skipped") = skippedIds.size
        dataflow("skipped_methods") = skipped.output
        phase("definition_accounting_completed")
        val options = new OssDataFlowOptions(maxNumberOfDefinitions = maxDefinitions)
        val passFailed = new AtomicBoolean(false)
        val methodsCompleted = new AtomicLong(0L)
        phase("dataflow_overlay_started")
        new OssDataFlow(options) {
          override def create(context: LayerCreatorContext): Unit = {
            new ReachingDefPass(context.cpg, maxDefinitions)(options.semantics) {
              override def runOnPart(dstGraph: DiffGraphBuilder, method: Method): Unit = {
                try {
                  val expected = definitionCounts(method.id)
                  // Do not pay for quadratic CFG/kill preparation merely to
                  // rediscover that a method exceeds the unchanged limit.
                  if (expected <= maxDefinitions) {
                    val problem = ReachingDefProblem.create(method)
                    val transfer = problem.transferFunction.asInstanceOf[ReachingDefTransferFunction]
                    val actual = transfer.gen.valuesIterator.map(_.size.toLong).sum
                    if (actual != expected) {
                      passFailed.set(true)
                      throw new IllegalStateException("Definition accounting mismatch")
                    }
                    val solution = new DataFlowSolver().calculateMopSolutionForwards(problem)
                    new DdgGenerator(options.semantics).addReachingDefEdges(dstGraph, method, problem, solution)
                  }
                  methodsCompleted.incrementAndGet()
                } catch { case NonFatal(error) =>
                  passFailed.set(true)
                  throw error
                }
              }
            }.createAndApply()
            // Parallel pass implementations can swallow worker exceptions.
            // Reject both explicit failures and any part that never completed
            // before LayerCreator.run can mark the overlay established.
            if (passFailed.get() || methodsCompleted.get() != definitionCounts.size.toLong)
              throw new IllegalStateException("Incomplete reaching definitions pass")
          }
        }.run(new LayerCreatorContext(cpg))
        if (!cpg.metaData.overlays.exists(_ == "dataflowOss"))
          throw new IllegalStateException("Dataflow overlay was not established")
        phase("dataflow_overlay_completed")
        dataflow("methods_analyzed") = methods.size - skippedIds.size
        given EngineContext = EngineContext(config = EngineConfig(maxCallDepth = maxCallDepth))
        val rows = new Bounded(20000, 8 * 1024 * 1024)
        val operationNames = Set("print", "println", "printf", "log", "warn", "error", "write", "writeFile",
          "writeFileSync", "appendFile", "open", "readFile", "readFileSync", "unlink", "remove", "rename",
          "execute", "executemany", "query", "exec", "execFile", "spawn", "run", "Popen", "system",
          "eval", "send", "sendall", "fetch", "request", "get", "post", "put", "delete")
        def owner(node: AstNode): Option[Method] = node match {
          case method: Method => Some(method)
          case _ => ancestors(node).collectFirst { case method: Method => method }
        }
        def flowNode(node: AstNode): Option[Obj] = owner(node).filter(locatedSource).flatMap { method =>
          val at = node.lineNumber.filter(_ > 0).orElse(node match {
            case _: MethodReturn => method.lineNumberEnd.filter(_ > 0).orElse(method.lineNumber)
            case _ => None
          })
          at.map { value => identityRow { Obj("path" -> text(method.filename), "line" -> value,
            "name" -> text(node match {
              case parameter: MethodParameterIn => parameter.name
              case identifier: Identifier => identifier.name
              case call: Call => call.name
              case _: MethodReturn | _: Return => "return"
              case _ => node.label
            }, 256), "method" -> text(method.fullName, 4096), "node_type" -> node.label) } }
        }
        // Reuse captured parameter sources across the graph. Restricting these
        // to each sink's own method loses caller inputs flowing into a callee
        // operation whose call result is discarded. Zero-parameter methods can
        // also contain sinks reached through captured values or returned calls.
        val parameters = methods.filterNot(method => skippedIds(method.id)).flatMap { method =>
          method.parameter.filter(parameter => parameter.index > 0 &&
            parameter.lineNumber.exists(_ > 0) && !Set("self", "this", "cls")(parameter.name))
        }
        val parameterIds = parameters.iterator.map(_.id).toSet
        dataflow("source_parameter_count") = parameters.size
        val parameterNodes: List[CfgNode] = parameters.toList.distinct
        // Parameter nodes are already their own Joern starting points. Calling
        // reachableByFlows for each sink repeats generic source/usage expansion
        // across every graph method, creates an executor and materializes all
        // returned paths before its Iterator can be limited. Use the qualified
        // engine directly, preserving source visibility and path semantics.
        val effectNames = Set("write", "writeFile", "writeFileSync", "appendFile", "open", "readFile", "readFileSync",
          "unlink", "remove", "rename", "execute", "executemany", "exec", "execFile", "spawn", "run", "Popen",
          "system", "eval", "send", "sendall", "fetch", "request", "post", "put", "delete")
        val categories = Vector("named_effect_hint", "lifecycle_name_hint", "source_supported_cross_file", "breadth")
        val lifecycleNames = Set("init", "__init__", "<init>", "start", "stop", "close", "shutdown", "setup",
          "teardown", "setUp", "tearDown", "bootstrap", "migrate", "_migrate", "initialize", "dispose", "cleanup")
        val lifecycleVerbs = Set("init", "initialize", "start", "stop", "close", "shutdown", "setup", "teardown",
          "bootstrap", "migrate", "dispose", "cleanup", "create", "archive", "restore", "recover", "reconcile",
          "approve", "authorize", "dispatch", "transition", "commit", "rollback", "delete", "update")
        def lifecycleHint(name: String): Boolean = lifecycleNames(name) || {
          val tokens = name.replaceAll("([a-z0-9])([A-Z])", "$1_$2")
            .replaceAll("([A-Z]+)([A-Z][a-z])", "$1_$2")
            .toLowerCase(java.util.Locale.ROOT).split("[^a-z0-9]+")
          tokens.exists(lifecycleVerbs)
        }
        val sourceRoot = Paths.get(cpgFile).toAbsolutePath.getParent.resolve("source").normalize.toString.replace('\\', '/')
        def relativeIdentity(value: String): String = value.replace('\\', '/').replace(sourceRoot + "/", "")
        def sha(value: String): String = samplingHex.formatHex(samplingDigest.digest(value.getBytes(UTF_8)))
        case class Endpoint(id: String, category: String, kind: String, node: CfgNode,
            method: Method, at: Int, locationBasis: String, skipped: Boolean)
        def endpoint(kind: String, node: CfgNode, method: Method, effect: Boolean): Endpoint = {
          val at = node.lineNumber.filter(_ > 0)
          val category = if (effect) categories(0)
            else if (lifecycleHint(method.name)) categories(1)
            else if (crossFileMethods(method.id)) categories(2) else categories(3)
          val ancestry = ancestors(node).takeWhile(_ != method).map(parent => Seq(parent.label,
            parent.lineNumber.toString, parent.columnNumber.toString,
            Option(parent.propertiesMap.get("ORDER")).map(_.toString).getOrElse("")).mkString("\u0000"))
            .mkString("\u0001")
          val identity = Seq(kind, relativeIdentity(method.filename), relativeIdentity(method.fullName),
            method.lineNumber.toString, node.lineNumber.toString, node.columnNumber.toString, node.label,
            Option(node.propertiesMap.get("ORDER")).map(_.toString).getOrElse(""),
            node match { case expression: Expression => expression.argumentIndex.toString; case _ => "" },
            node match { case reference: MethodRef => relativeIdentity(reference.methodFullName); case _ => "" },
            relativeIdentity(node.code), ancestry).mkString("\u0000")
          Endpoint(sha(identity), category, kind, node, method, at.getOrElse(method.lineNumber.get),
            if (at.nonEmpty) "node_line" else "method_line", skippedIds(method.id))
        }
        val sinks = methods.flatMap { method =>
          val returns = method.ast.isReturn.filter(node => owner(node).exists(_.id == method.id))
            .map(node => endpoint("parameter_to_return", node, method, false)).toVector
          val operations = method.ast.isCall.filter(call => owner(call).exists(_.id == method.id) &&
              operationNames(call.name))
            .flatMap(call => call.argument.filter(_.argumentIndex > 0)
              .map(node => endpoint("parameter_to_operation", node, method, effectNames(call.name))))
            .toVector
          returns ++ operations
        }
        // The selection cap bounds endpoint work, not graph/source capture.
        // Each category gets a turn, including reserved general breadth. Within
        // each category, files and then methods rotate before taking another
        // endpoint. SHA source identities, never graph IDs, determine ordering.
        def roundRobin[A](groups: Vector[Iterator[A]]): Iterator[A] = new Iterator[A] {
          private val active = mutable.Queue.from(groups.filter(_.hasNext))
          override def hasNext: Boolean = active.nonEmpty
          override def next(): A = {
            val group = active.dequeue()
            val value = group.next()
            if (group.hasNext) active.enqueue(group)
            value
          }
        }
        val eligible = sinks.filterNot(_.skipped)
        def categoryPlan(category: String): Iterator[Endpoint] = {
          val files = eligible.filter(_.category == category).groupBy(_.method.filename).toVector
            .sortBy { case (path, _) => sha(relativeIdentity(path)) }
          roundRobin(files.map { case (_, endpoints) =>
            val methodGroups = endpoints.groupBy(endpoint =>
              (relativeIdentity(endpoint.method.fullName), endpoint.method.lineNumber)).toVector
              .sortBy { case ((name, at), _) => sha(name + "\u0000" + at.toString) }
            roundRobin(methodGroups.map { case (_, values) => values.sortBy(_.id).iterator })
          })
        }
        val selectionLimit = 2048
        val selected = roundRobin(categories.map(categoryPlan)).take(selectionLimit).toVector
        if (selected.map(_.id).distinct.size != selected.size)
          throw new IllegalStateException("Ambiguous endpoint source identities")
        val planDigest = sha(selected.map(_.id).mkString("\n"))
        dataflow("selection") = Obj("policy" -> "priority_file_method_round_robin_v1", "limit" -> selectionLimit,
          "plan_digest" -> planDigest, "endpoints" -> Arr.from(selected.map(endpoint =>
            Obj("id" -> endpoint.id, "category" -> endpoint.category, "kind" -> endpoint.kind,
              "path" -> text(endpoint.method.filename), "line" -> endpoint.at,
              "location_basis" -> endpoint.locationBasis))))
        val sinksTotal = sinks.size.toLong
        val categoryCandidates = eligible.groupMapReduce(_.category)(_ => 1L)(_ + _)
        val categorySelected = selected.groupMapReduce(_.category)(_ => 1L)(_ + _)
        var sinksQueried = 0L
        var engineQueries = 0L
        var engineQueriesStarted = 0L
        var provenEmpty = 0L
        var pathsTruncated = 0L
        val categoryQueried = mutable.Map.from(categories.map(_ -> 0L))
        val flowBegan = System.nanoTime()
        val flowDeadline = began + flowSeconds.toLong * 1000000000L
        var maximumEndpointSeconds = 0.0
        var currentEndpointStarted: Option[Double] = None
        def number(value: Long): Num = Num(value.toDouble)
        def categoryCounts: Obj = Obj.from(categories.map(category => category -> Obj(
          "candidates" -> number(categoryCandidates.getOrElse(category, 0L)),
          "selected" -> number(categorySelected.getOrElse(category, 0L)),
          "queried" -> number(categoryQueried(category)))))
        def updateFlow(finished: Boolean): Unit = {
          val output = rows.output
          val missing = skippedIds.nonEmpty || eligible.size > selected.size || sinksQueried < selected.size
          val lowerBound = missing || pathsTruncated > 0
          val incomplete = lowerBound || output("omitted").num > 0
          output("count_is_lower_bound") = Bool(lowerBound)
          if (incomplete) output("status") = Str("partial")
          dataflow("paths") = output
          dataflow("queries") = Obj("sinks_total" -> number(sinksTotal),
            "sinks_eligible" -> eligible.size, "sinks_selected" -> selected.size,
            "sinks_not_selected" -> (eligible.size - selected.size),
            "sinks_skipped" -> (sinks.size - eligible.size),
            "sinks_pending" -> number(selected.size.toLong - sinksQueried),
            "sinks_queried" -> number(sinksQueried), "sinks_omitted" -> number(sinksTotal - sinksQueried),
            "engine_queries" -> number(engineQueries), "sinks_proven_empty" -> number(provenEmpty),
            "paths_truncated" -> number(pathsTruncated), "step_limit" -> stepLimit,
            "by_category" -> categoryCounts)
          dataflow("status") = Str(if (finished && !incomplete) "complete" else "partial")
          result("dataflow") = dataflow("status")
        }
        def progress(stage: String): Unit = {
          writeResult(Obj("schema_version" -> 1, "query_version" -> "8", "run_token" -> runToken,
            "base_sha256" -> baseSha256, "plan_digest" -> planDigest, "stage" -> stage,
            "source_parameter_count" -> parameters.size, "sinks_total" -> number(sinksTotal),
            "sinks_eligible" -> eligible.size, "sinks_selected" -> selected.size,
            "sinks_not_selected" -> (eligible.size - selected.size), "sinks_skipped" -> (sinks.size - eligible.size),
            "sinks_queried" -> number(sinksQueried), "sinks_pending" -> number(selected.size.toLong - sinksQueried),
            "engine_queries" -> number(engineQueries), "engine_queries_started" -> number(engineQueriesStarted),
            "sinks_proven_empty" -> number(provenEmpty), "by_category" -> categoryCounts,
            "flow_budget_seconds" -> flowSeconds, "budget_origin" -> "query_body_start",
            "elapsed_seconds" -> Num((System.nanoTime() - began).toDouble / 1e9),
            "flow_elapsed_seconds" -> Num((System.nanoTime() - flowBegan).toDouble / 1e9),
            "current_endpoint_started_seconds" -> currentEndpointStarted.map(Num(_)).getOrElse(Null),
            "maximum_endpoint_seconds" -> Num(maximumEndpointSeconds)), out + ".flow-progress.json")
        }
        var lastCheckpointAt = flowBegan
        var lastCheckpointCount = 0L
        var firstWitnessSaved = false
        def flowCheckpoint(): Unit = {
          updateFlow(false)
          val snapshot = ujson.read(ujson.write(dataflow))
          writeResult(Obj("schema_version" -> 1, "query_version" -> "8", "checkpoint" -> "dataflow_progress",
            "run_token" -> runToken, "base_sha256" -> baseSha256,
            "overlays" -> Arr.from(cpg.metaData.overlays.toVector.distinct.sorted),
            "truncated_values" -> number(truncatedValues), "dataflow_analysis" -> snapshot), out + ".flow.json")
          lastCheckpointAt = System.nanoTime()
          lastCheckpointCount = sinksQueried
          if (rows.count > 0) firstWitnessSaved = true
        }
        phase("dataflow_queries_started")
        flowCheckpoint()
        progress("ready")
        val engine = new Engine(summon[EngineContext])
        try selected.iterator.takeWhile(_ => System.nanoTime() < flowDeadline).foreach { endpoint =>
          val kind = endpoint.kind
          val sink = endpoint.node
          val endpointBegan = System.nanoTime()
          currentEndpointStarted = Some((endpointBegan - began).toDouble / 1e9)
          // Keep the original per-endpoint query shape and peak-memory scope;
          // share the executor without generic source/usage expansion.
          val empty = provenEmptyStarter(sink)
          val entries = if (empty) List.empty[io.joern.dataflowengineoss.queryengine.TableEntry] else {
            engineQueriesStarted += 1
            progress("querying")
            engine.backwards(List(sink), parameterNodes)
          }
          val paths = entries.iterator.filter { entry =>
            entry.path.headOption.forall(first => first.visible || parameterIds(first.node.id))
          }.map { entry =>
            val visible = entry.path.filter(element => element.visible || parameterIds(element.node.id))
              .map(_.node)
            visible.headOption.map(first => first +: visible.sliding(2).collect {
              case Seq(a, b) if a != b => b
            }.toVector).getOrElse(Vector.empty)
          }.distinct.take(pathsPerSink + 1).toVector
          if (paths.size > pathsPerSink) pathsTruncated += 1
          paths.take(pathsPerSink).foreach { path =>
            val elements = path
            val mapped = elements.take(stepLimit + 1).map(flowNode)
            if (elements.size > stepLimit || mapped.exists(_.isEmpty) ||
                mapped.flatten.exists(_("identity_truncated").bool) || mapped.size < 2) pathsTruncated += 1
            else {
              val steps = mapped.flatten
              val source = steps.head
              val endPoint = steps.last
              // A source must actually be a captured parameter selected
              // above; no unknown/imported value is silently classified.
              if (!parameterIds(elements.head.id) || elements.last.id != sink.id) pathsTruncated += 1
              else rows.add(Obj("kind" -> kind, "endpoint_id" -> endpoint.id, "source" -> source, "sink" -> endPoint,
                "steps" -> Arr.from(steps),
                "interprocedural" -> Bool(steps.map(_("method").str).distinct.size > 1)))
            }
          }
          // A completed prefix includes only fully returned AND normalized
          // endpoints. An in-flight engine call remains pending on interruption.
          if (empty) provenEmpty += 1 else engineQueries += 1
          sinksQueried += 1
          categoryQueried(endpoint.category) += 1
          maximumEndpointSeconds = math.max(maximumEndpointSeconds, (System.nanoTime() - endpointBegan).toDouble / 1e9)
          currentEndpointStarted = None
          if ((!firstWitnessSaved && rows.count > 0) || sinksQueried - lastCheckpointCount >= 64 ||
              System.nanoTime() - lastCheckpointAt >= 15000000000L) {
            flowCheckpoint()
            progress("ready")
          }
        } finally engine.shutdown()
        flowCheckpoint()
        progress(if (sinksQueried < selected.size) "budget_exhausted" else "finished")
        phase("dataflow_queries_completed")
        updateFlow(true)
        result("metadata")("overlays") = Arr.from(cpg.metaData.overlays.toVector.distinct.sorted)
        var reachingEdges = 0L
        var edgesAfterDataflow = 0L
        cpg.graph.allEdges.foreach { edge =>
          edgesAfterDataflow += 1
          if (edge.label == "REACHING_DEF") reachingEdges += 1
        }
        result("metrics")("edge_counts")("REACHING_DEF") = Num(reachingEdges.toDouble)
        result("metrics")("edges") = Num(edgesAfterDataflow.toDouble)
      } catch { case NonFatal(error) =>
        result("dataflow") = Str("error")
        dataflow("status") = Str("error")
        errors.value += Obj("section" -> "dataflow_analysis", "error" -> error.getClass.getName)
      }
    }
  } catch { case NonFatal(error) =>
    errors.value += Obj("section" -> "load_or_overlays", "error" -> error.getClass.getName)
  } finally {
    result("truncated_values") = Num(truncatedValues.toDouble)
    if (truncatedValues > 0) gaps.value += Str("Overlong source-derived names or paths were truncated; identity checks may reject those rows.")
    val incompleteSections = Seq("source_files", "methods", "calls", "module_edges", "inferred_module_edges", "unread_bindings", "dataflow_analysis").filter { name =>
      result.obj.get(name).exists(value => value.obj.get("status").exists(_.str != "complete"))
    }
    incompleteSections.foreach(name => gaps.value += Str(s"$name is incomplete or unsupported; inspect its status and omission counts."))
    val partial = errors.value.nonEmpty || truncatedValues > 0 || incompleteSections.nonEmpty
    result("status") = Str(if (partial) "partial" else "complete")
    writeResult(result)
  }
}
