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
		set(cast(size_t)(fmix(data) % map.length));
	}

	void put(ulong data) pure nothrow @nogc
	{
		set(cast(size_t)(fmix(data) % map.length));
	}

	void put(UUID data) pure nothrow @nogc
	{
		set(data.toHash % map.length);
	}

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
