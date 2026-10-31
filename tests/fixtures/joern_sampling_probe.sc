// Assertion body combined with the actual bundled query helpers by scripts/test-joern-sampling.py.
  case class Item(path: String, key: String, payload: String, graphId: Long)
  def sample(input: Vector[Item], cap: Int, bytes: Int, metadata: Int): Obj = {
    val counts = input.groupMapReduce(_.path)(_ => 1L)(_ + _)
    val selected = new FairRows[Item](counts, cap, bytes, metadata)
    input.foreach(item => selected.add(item.path, item.key)(item))
    selected.output(item => Obj("path" -> item.path, "key" -> item.key, "payload" -> item.payload))
  }
  val skew = (0 until 1000).map(i => Item("a-large.py", f"$i%05d", "short", i.toLong)).toVector ++
    (0 until 3).map(i => Item("z-owner.py", f"$i%05d", "short", 2000L + i)) ++
    (0 until 2).map(i => Item("zz-owner.py", f"$i%05d", "short", 3000L + i))
  val forward = sample(skew, 30, 20000, 1024)
  val reversed = sample(skew.reverse.map(item => item.copy(graphId = 99999L-item.graphId)), 30, 20000, 1024)
  val shuffled = sample(new scala.util.Random(42).shuffle(skew), 30, 20000, 1024)
  assert(ujson.write(forward) == ujson.write(reversed))
  assert(ujson.write(forward) == ujson.write(shuffled))
  val coverage = forward("file_coverage")("rows").arr.map(row => row("path").str -> row("retained").num.toInt).toMap
  assert(coverage == Map("a-large.py" -> 25, "z-owner.py" -> 3, "zz-owner.py" -> 2))
  assert(forward("count").num == 1005 && forward("omitted").num == 975)
  assert(forward("source_files").num == 3 && forward("omitted_files").num == 0)
  val pressure = Vector(Item("a.py", "0", "X" * 2000, 1), Item("a.py", "1", "tiny", 2)) ++
    (0 until 30).map(i => Item("b.py", f"$i%05d", "tiny", 3L+i)) ++
    Vector(Item("c.py", "0", "tiny", 40))
  val bytes = sample(pressure, 8, 6000, 512)
  assert(bytes("byte_omissions").num == 1)
  assert(bytes("retained_files").num == 3)
  assert(bytes("rows").arr.size == 7)
  assert(ujson.write(bytes) == ujson.write(sample(pressure.reverse, 8, 6000, 512)))
  assert(ujson.write(bytes).getBytes(UTF_8).length <= 6000)
  val unicodeInput = Vector(Item("unicode.py", "0", "🧭" * 250, 1),
    Item("unicode.py", "1", "漢" * 250, 2), Item("unicode.py", "2", "tiny", 3))
  val unicode = sample(unicodeInput, 3, 6000, 512)
  assert(unicode("byte_omissions").num == 1 && unicode("rows").arr.size == 2)
  assert(ujson.write(unicode).getBytes(UTF_8).length <= 6000)
  val many = (0 until 1000).map(i => Item(f"path-$i%04d.py", "0", "small", i)).toVector
  val bounded = sample(many, 50, 6000, 256)
  assert(bounded("source_files").num == 1000)
  assert(bounded("omitted_files").num > 0)
  assert(bounded("file_coverage")("omitted").num > 0)
  assert(ujson.write(bounded).getBytes(UTF_8).length <= 6000)
  val empty = sample(Vector.empty, 20, 6000, 256)
  assert(empty("status").str == "complete" && empty("rows").arr.isEmpty)
  val relativeKey = methodSamplingKey("/private/a/source", "src/tool.py", 3, 5,
    "run", "src/tool.py:<module>.run", false, false, true)
  val absoluteKey = methodSamplingKey("/private/longer/b/source", "/private/longer/b/source/src/tool.py", 3, 5,
    "run", "/private/longer/b/source/src/tool.py:<module>.run", false, false, true)
  val mixedKey = methodSamplingKey("/private/c/source", "src/tool.py", 3, 5,
    "run", "/private/c/source/src/tool.py:<module>.run", false, false, true)
  assert(relativeKey == absoluteKey && relativeKey == mixedKey)
  assert(relativeKey != methodSamplingKey("/private/a/source", "src/tool.py", 4, 5,
    "run", "src/tool.py:<module>.run", false, false, true))
  assert(relativeKey != methodSamplingKey("/private/a/source", "src/tool.py", 3, 5,
    "run", "src/tool.py:<module>.run", true, false, true))
  val checks = Obj("status" -> "passed", "skew_and_spare_redistribution" -> true,
    "traversal_and_graph_id_independence" -> true, "private_root_independent_hash_rank" -> true, "oversized_row_does_not_starve_other_files" -> true,
    "utf8_total_byte_bound" -> true, "file_metadata_bounds_explicit" -> true, "empty_input" -> true,
    "skew_sample" -> forward, "byte_pressure_sample" -> bytes,
    "metadata_pressure_counts" -> Obj("files" -> bounded("source_files"), "omitted_files" -> bounded("omitted_files"),
      "metadata_omitted" -> bounded("file_coverage")("omitted")))
  checks("max_heap_bytes") = Num(Runtime.getRuntime.maxMemory.toDouble)
  checks("active_processors") = Runtime.getRuntime.availableProcessors
  checks("java_version") = System.getProperty("java.version")
  Files.writeString(Paths.get(out), ujson.write(checks))
