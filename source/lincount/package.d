module lincount;

import std.range.primitives;
import std.traits;

/++
Simple Linear Probabilistic Counter.
+/
struct LPCounter
{
	import mir.ndslice.allocation: slice;
	import mir.ndslice.slice;
	import mir.ndslice.field: BitwiseField;
	import mir.ndslice.iterator: FieldIterator;
	import mir.ndslice.topology: bitwise;

	import std.uuid: UUID;

	private Slice!(SliceKind.contiguous, [1], FieldIterator!(BitwiseField!(size_t*))) map;
	private size_t _length = 0;

	@disable this();

	private void set(size_t index) pure nothrow @nogc
	{
		if(map[index] == false)
		{
			map[index] = true;
			_length++;
		}
	}

	/// Constructs counter with appropriate size.
	this(size_t kilobytes) pure nothrow
	{
		map = slice!size_t(1024 * kilobytes / size_t.sizeof).bitwise;
		_length = 0;
	}

	/++
	Constructs counter with predefined dump.
	Params:
		dump = 8-byte aligned non-empty data. `dump` must be rounded to kilobytes: `dump.length % 1024 == 0`.
	+/
	this(void[] dump) pure
	{
		if (dump.length % 1024)
			throw new Exception("LPCounter: dump is broken.");
		map = sliced(cast(size_t[])dump).bitwise;
		import mir.ndslice.algorithm: count;
		_length = map.count!"a"; // uses popcnt / llvm_ctpop
	}

	/++
	Puts integer to a counter.
	+/
	void put(uint data) pure nothrow @nogc
	{
		set(cast(size_t)(fmix(data) % map.length));
	}

	/// ditto
	void put(ulong data) pure nothrow @nogc
	{
		set(cast(size_t)(fmix(data) % map.length));
	}

	/// Puts `UUID` to a counter.
	void put(UUID data) pure nothrow @nogc
	{
		set(data.toHash % map.length);
	}

	/// Puts raw data to a counter.
	void put(in void[] data) pure nothrow @nogc
	{
		//hashOf(data);
		static if (__VERSION__ >= 2072)
		{
			import std.digest.digest: digest;
			import std.digest.murmurhash: MurmurHash3;
			alias D = MurmurHash3!(128, 64);
		}
		else
		{
			import lincount.murmurhash;
			alias D = MurmurHash3_x64_128;
		}
		auto hashed = cast(ulong[2])digest!D(data);
		set((hashed[0] ^ hashed[1]) % map.length);
	}

	/// Returns: approximate number of elements.
	ulong count() nothrow @nogc
	{
		import std.math: log, lround;
		if(map.length > _length)
			return lround(map.length * -log(real(map.length - _length) / map.length));
		else
			return map.length;
	}

	/// Returns: size of the counter in kilobytes.
	size_t size() @property pure nothrow @nogc
	{
		return map.length() / (size_t.sizeof * 1024);
	}

	/// Returns: raw representation of a counter.
	const(ubyte)[] dump() const pure nothrow @nogc
	out(res) {
		assert(res.length % 1024 == 0);
	}
	body {
		return cast(ubyte[]) map._iterator._field._field[0 .. map.length / (size_t.sizeof * 8)];
	}
}

///
unittest
{
	auto counter = LPCounter(32);
	counter.put(100U);
	counter.put(100UL);
	counter.put("100");
	assert(counter.count == 3);
	counter.put("101");
	assert(counter.count == 4);
}

/++
Merges a range of $(LREF LPCounter)s into a single one.
Params:
	counters = non empty range. All counters must have the same sizes.
Returns: union counter
+/
LPCounter mergeLPCounters(Range)(Range counters)
	if (isInputRange!Range && (is(ElementType!Range : const(LPCounter)) || is(ElementType!Range : const(LPCounter)*)))
{
	import std.exception;
	enforce(!counters.empty, "Range of counters must not be empty");
	auto repr = cast(size_t[])counters.front.dump.dup;
	counters.popFront;
	enforce(repr.length);
	foreach (counter; counters)
	{
		auto r = cast(const(size_t)[])counter.dump;
		enforce (r.length == repr.length, "All counters must have the same sizes.");
		repr[] |= r[];
	}
	return LPCounter(repr);
}

///
unittest
{
	auto a = LPCounter(32);
	a.put(100U);
	a.put(100UL);
	a.put("100");
	assert(a.count == 3);
	
	auto b = LPCounter(32);
	b.put(100U); // intersection
	b.put(200U);
	b.put("LP");
	assert(b.count == 3);

	auto c = mergeLPCounters([a, b]);
	assert(c.count == 5);
}

// Murmurhash mix
private:

uint fmix(uint h) pure nothrow @nogc
{
    h ^= h >> 16;
    h *= 0x85ebca6b;
    h ^= h >> 13;
    h *= 0xc2b2ae35;
    h ^= h >> 16;
    return h;
}

ulong fmix(ulong k) pure nothrow @nogc
{
    k ^= k >> 33;
    k *= 0xff51afd7ed558ccd;
    k ^= k >> 33;
    k *= 0xc4ceb9fe1a85ec53;
    k ^= k >> 33;
    return k;
}
