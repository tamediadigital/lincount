module lincount;

struct LPCounter
{
	import std.bitmanip: BitArray;
	import std.uuid: UUID;

	private BitArray map;
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

	this(size_t kilobytes) pure nothrow
	{
		map.length = 8 * 1024 * kilobytes;
		_length = 0;
	}

	this(void[] dump) pure
	{
		if (dump.length % 1024)
			throw new Exception("LPCounter: dump is broken.");
		map = BitArray(dump, dump.length * 8);
		import std.range.primitives: walkLength;
		_length = map.bitsSet.walkLength;
	}

	void put(uint data) pure nothrow @nogc
	{
		import lincount.internal: fmix;
		set(cast(size_t)(fmix(data) % map.length));
	}

	void put(ulong data) pure nothrow @nogc
	{
		import lincount.internal: fmix;
		set(cast(size_t)(fmix(data) % map.length));
	}

	void put(UUID data) pure nothrow @nogc
	{
		set(data.toHash % map.length);
	}

	void put(in void[] data) pure nothrow @nogc
	{
		//hashOf(data);
		import std.digest.digest: digest;
		import lincount.internal: MurmurHash3_x64_128;
		auto hashed = cast(ulong[2])digest!MurmurHash3_x64_128(data);
		set((hashed[0] ^ hashed[1]) % map.length);
	}

	ulong count() nothrow @nogc
	{
		import std.math: log, lround;
		if(map.length > _length)
			return lround(map.length * -log(real(map.length - _length) / map.length));
		else
			return map.length;
	}

	//returns the size of the underlying BitArray in KB
	@property size_t size() pure nothrow @nogc
	{
		return map.length() / (8 * 1024);
	}

	const(ubyte)[] dump() pure nothrow @nogc
	out(res) {
		assert(res.length % 1024 == 0);
	}
	body {
		return cast(ubyte[]) cast(void[]) map;
	}
}
