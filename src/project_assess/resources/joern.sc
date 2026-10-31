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
  val result = Obj("schema_version" -> 1, "query_version" -> "3", "dataflow" -> "not_run",
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
      val rows = new Bounded(4000, 256 * 1024)
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
      val rows = new FairRows[Method](counts.toMap, 20000, 6 * 1024 * 1024, 256 * 1024)
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
      val rows = new Bounded(10000, 8 * 1024 * 1024)
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
  } catch { case NonFatal(error) =>
    errors.value += Obj("section" -> "load_or_overlays", "error" -> error.getClass.getName)
  } finally {
    result("truncated_values") = Num(truncatedValues.toDouble)
    if (truncatedValues > 0) gaps.value += Str("Overlong source-derived names or paths were truncated; identity checks may reject those rows.")
    val incompleteSections = Seq("source_files", "methods", "calls", "module_edges", "inferred_module_edges", "unread_bindings").filter { name =>
      result.obj.get(name).exists(value => value.obj.get("status").exists(_.str != "complete"))
    }
    incompleteSections.foreach(name => gaps.value += Str(s"$name is incomplete or unsupported; inspect its status and omission counts."))
    val partial = errors.value.nonEmpty || truncatedValues > 0 || incompleteSections.nonEmpty
    result("status") = Str(if (partial) "partial" else "complete")
    Files.writeString(Paths.get(out), ujson.write(result))
  }
}
