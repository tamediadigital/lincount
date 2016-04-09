module lincount;

struct LPCounter
{
	import std.bitmanip: BitArray;
	import std.uuid: UUID;

	private BitArray map;
	private size_t _length = 0;

	@disable this();

	private void set(size_t index)
	{
		if(map[index] == false)
		{
			map[index] = true;
			_length++;
		}
	}

	this(size_t kilobytes)
	{
		map.length = 8 * 1024 * kilobytes;
		_length = 0;
	}

	void put(uint data)
	{
		import lincount.internal: fmix;
		set(cast(size_t)(fmix(data) % map.length));
	}

	void put(ulong data)
	{
		import lincount.internal: fmix;
		set(cast(size_t)(fmix(data) % map.length));
	}

	void put(UUID data)
	{
		set(data.toHash % map.length);
	}

	void put(in void[] data)
	{
		//hashOf(data);
		import std.digest.digest: digest;
		import lincount.internal: MurmurHash3_x64_128;
		auto hashed = cast(ulong[2])digest!MurmurHash3_x64_128(data);
		set((hashed[0] ^ hashed[1]) % map.length);
	}

	ulong count()
	{
		import std.math: log, lround;
		if(map.length > _length)
			return lround(map.length * -log(real(map.length - _length) / map.length));
		else
			return map.length;
	}
}
