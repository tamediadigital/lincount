/**
Computes MurmurHash hashes of arbitrary data. MurmurHash is a non-cryptographic
hash function suitable for general hash-based lookup.

This module conforms to the APIs defined in $(D std.digest.digest).

This module publicly imports $(D std.digest.digest) and can be used as a stand-alone module.

Note: The current implementation is optimized for little endian architectures.
It will exhibit different results on big endian architectures and a slightly less uniform distribution.

License: $(WEB www.boost.org/LICENSE_1_0.txt, Boost License 1.0).
Authors: Guillaume Chatelet
References: $(LINK2 https://code.google.com/p/smhasher/wiki/MurmurHash3, Reference implementation)
$(BR) $(LINK2 https://en.wikipedia.org/wiki/MurmurHash, Wikipedia on MurmurHash)
*/
/* Copyright Guillaume Chatelet 2016.
 * Distributed under the Boost Software License, Version 1.0.
 * (See LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
 */
//module std.digest.murmurhash;
module lincount.internal;

public import std.digest.digest;

@safe:

///
unittest
{
    // MurmurHash3_x86_32, MurmurHash3_x86_128 and MurmurHash3_x64_128 implement
    // std.digest.digest Template API.
    static assert(isDigest!MurmurHash3_x86_32);
    // The convenient digest template allows for quick hashing of data.
    auto hashed = digest!MurmurHash3_x86_32([1, 2, 3, 4]);
}

///
unittest
{
    // One can also hash ubyte data piecewise.
    const(ubyte)[] data1 = [1, 2, 3];
    const(ubyte)[] data2 = [4, 5, 6, 7];
    MurmurHash3_x86_32 hasher;
    hasher.put(data1);
    hasher.put(data2);
    auto hashed = hasher.finish();
}

///
unittest
{
    // Using SMurmurHash3_x86_32, SMurmurHash3_x86_128 and SMurmurHash3_x64_128
    // you gain full control over which part of the algorithm to run.
    // This allows for maximum throughput but needs extra care.

    // Data type must be the same as the hasher's element type:
    // - uint for SMurmurHash3_x86_32
    // - ulong[2] for SMurmurHash3_x86_128 and SMurmurHash3_x64_128
    const(uint)[] data = [1, 2, 3, 4];
    // Note the hasher starts with S.
    SMurmurHash3_x86_32 hasher;
    // Push as many array of elements as you need. The less call the better performance wise.
    hasher.putBlocks(data);
    // Put remainder bytes if needed. This method can be called only once.
    hasher.putRemainder(ubyte(1), ubyte(1), ubyte(1));
    // Call finalize to incorporate data length in the hash.
    hasher.finalize();
    // Finally get the hashed value.
    auto hashed = hasher.getBytes();
}

/// Implements MurmurHash3_x86_32 $(D std.digest.digest) Template API.
alias MurmurHash3_x86_32 = Piecewise!SMurmurHash3_x86_32;
/// Implements MurmurHash3_x86_128 $(D std.digest.digest) Template API.
alias MurmurHash3_x86_128 = Piecewise!SMurmurHash3_x86_128;
/// Implements MurmurHash3_x64_128 $(D std.digest.digest) Template API.
alias MurmurHash3_x64_128 = Piecewise!SMurmurHash3_x64_128;

/// Implements MurmurHash3_x86_32 $(D std.digest.digest.Digest) OOO API.
alias MurmurHash3_x86_32Digest = WrapperDigest!MurmurHash3_x86_32;
/// Implements MurmurHash3_x86_128 $(D std.digest.digest.Digest) OOO API.
alias MurmurHash3_x86_128Digest = WrapperDigest!MurmurHash3_x86_128;
/// Implements MurmurHash3_x64_128 $(D std.digest.digest.Digest) OOO API.
alias MurmurHash3_x64_128Digest = WrapperDigest!MurmurHash3_x64_128;

// This definition of NO_UNALIGNED_ACCESS is too restrictive. Only a few old
// SPARC/ARM chips cannot do unaligned reads.
version(ARM)   { version = NO_UNALIGNED_ACCESS; }
version(SPARC) { version = NO_UNALIGNED_ACCESS; }

/**
Pushes an array of blocks at once. It is more efficient to push as much data as
possible in a single call.
On platform that does not support unaligned reads (some old ARM chips), it is
forbidden to pass non aligned data.
*/
void putBlocks(H, Block = H.Block)(ref H hasher, scope const(Block[]) blocks...) pure nothrow @nogc
in
{
    version(NO_UNALIGNED_ACCESS) assert(blocks.ptr % Block.alignof == 0);
}
body
{
    foreach (const block; blocks)
    {
        hasher.putBlock(block);
    }
    hasher.size += blocks.length * Block.sizeof;
}

/**
Returns the current hashed value as an ubyte array.
*/
auto getBytes(H)(ref H hash) pure nothrow @nogc
{
    static if (is(H.Block == uint))
    {
        return cast(ubyte[H.Block.sizeof]) cast(uint[1])[hash.get()];
    }
    else
    {
        return cast(ubyte[H.Block.sizeof]) hash.get();
    }
}

/**
MurmurHash3 for x86 processors producing a 32 bits value.

This is a lower level implementation that makes finalization optional and have slightly better performance.
Note that $(D putRemainder) can be called only once and that no subsequent calls to $(D putBlocks) is allowed.
*/
struct SMurmurHash3_x86_32
{
private:
    enum uint c1 = 0xcc9e2d51;
    enum uint c2 = 0x1b873593;
    uint h1;

public:
    alias Block = uint; /// The element size for x86_32 implementation.
    size_t size;

    this(uint seed)
    {
        h1 = seed;
    }

    @disable this(this);

    /// Adds a single Block of data without increasing size.
    /// Make sure to increase size by Block.sizeof for each call to putBlock.
    void putBlock(uint block) pure nothrow @nogc
    {
        update(h1, block, 0, c1, c2, 15, 13, 0xe6546b64);
    }

    /// Put remainder bytes. This must be called only once after putBlock and before finalize.
    void putRemainder(scope const(ubyte[]) data...) pure nothrow @nogc
    {
        assert(data.length < Block.sizeof);
        assert(data.length >= 0);
        size += data.length;
        uint k1 = 0;
        final switch (data.length & 3)
        {
        case 3:
            k1 ^= data[2] << 16;
            goto case;
        case 2:
            k1 ^= data[1] << 8;
            goto case;
        case 1:
            k1 ^= data[0];
            h1 ^= shuffle(k1, c1, c2, 15);
            goto case;
        case 0:
        }
    }

    /// Incorporate size and finalizes the hash.
    void finalize() pure nothrow @nogc
    {
        h1 ^= size;
        h1 = fmix(h1);
    }

    /// Returns the hash as an uint value.
    Block get() pure nothrow @nogc
    {
        return h1;
    }
}

version (unittest)
{
    import std.string : representation;

    auto hash(H, Block = H.Block)(string data)
    {
        H hasher;
        immutable blocks = data.length / Block.sizeof;
        hasher.putBlocks(cast(const(Block)[]) data[0 .. blocks * Block.sizeof]);
        hasher.putRemainder(cast(const(ubyte)[]) data[blocks * Block.sizeof .. $]);
        hasher.finalize();
        return hasher.getBytes();
    }

    void checkResult(H)(in string[string] groundtruth)
    {
        foreach (data, expectedHash; groundtruth)
        {
            alias PiecewiseH = Piecewise!H;
            assert(data.digest!PiecewiseH.toHexString() == expectedHash);
            assert(data.hash!H.toHexString() == expectedHash);
            PiecewiseH hasher;
            foreach (element; data)
            {
                hasher.put(element);
            }
            assert(hasher.finish.toHexString() == expectedHash);
        }
    }
}

unittest
{
    checkResult!SMurmurHash3_x86_32([
        "" : "00000000",
        "a" : "B269253C",
        "ab" : "5FD7BF9B",
        "abc" : "FA93DDB3",
        "abcd" : "6A67ED43",
        "abcde" : "F69A9BE8",
        "abcdef" : "85C08161",
        "abcdefg" : "069B3C88",
        "abcdefgh" : "C4CCDD49",
        "abcdefghi" : "F0061442",
        "abcdefghij" : "91779288",
        "abcdefghijk" : "DF253B5F",
        "abcdefghijkl" : "273D6FA3",
        "abcdefghijklm" : "1B1612F2",
        "abcdefghijklmn" : "F06D52F8",
        "abcdefghijklmno" : "D2F7099D",
        "abcdefghijklmnop" : "ED9162E7",
        "abcdefghijklmnopq" : "4A5E65B6",
        "abcdefghijklmnopqr" : "94A819C2",
        "abcdefghijklmnopqrs" : "C15BBF85",
        "abcdefghijklmnopqrst" : "9A711CBE",
        "abcdefghijklmnopqrstu" : "ABE7195A",
        "abcdefghijklmnopqrstuv" : "C73CB670",
        "abcdefghijklmnopqrstuvw" : "1C4D1EA5",
        "abcdefghijklmnopqrstuvwx" : "3939F9B0",
        "abcdefghijklmnopqrstuvwxy" : "1A568338",
        "abcdefghijklmnopqrstuvwxyz" : "6D034EA3"]);
}

/**
MurmurHash3 for x86 processors producing a 128 bits value.

This is a lower level implementation that makes finalization optional and have slightly better performance.
Note that $(D putRemainder) can be called only once and that no subsequent calls to $(D putBlocks) is allowed.
*/
struct SMurmurHash3_x86_128
{
private:
    enum uint c1 = 0x239b961b;
    enum uint c2 = 0xab0e9789;
    enum uint c3 = 0x38b34ae5;
    enum uint c4 = 0xa1e38b93;
    uint h4, h3, h2, h1;

public:
    alias Block = uint[4]; /// The element size for x86_128 implementation.
    size_t size;

    this(uint seed4, uint seed3, uint seed2, uint seed1)
    {
        h4 = seed4;
        h3 = seed3;
        h2 = seed2;
        h1 = seed1;
    }

    this(uint seed)
    {
        h4 = h3 = h2 = h1 = seed;
    }

    @disable this(this);

    /// Adds a single Block of data without increasing size.
    /// Make sure to increase size by Block.sizeof for each call to putBlock.
    void putBlock(Block block) pure nothrow @nogc
    {
        update(h1, block[0], h2, c1, c2, 15, 19, 0x561ccd1b);
        update(h2, block[1], h3, c2, c3, 16, 17, 0x0bcaa747);
        update(h3, block[2], h4, c3, c4, 17, 15, 0x96cd1c35);
        update(h4, block[3], h1, c4, c1, 18, 13, 0x32ac3b17);
    }

    /// Put remainder bytes. This must be called only once after putBlock and before finalize.
    void putRemainder(scope const(ubyte[]) data...) pure nothrow @nogc
    {
        assert(data.length < Block.sizeof);
        assert(data.length >= 0);
        size += data.length;
        uint k1 = 0;
        uint k2 = 0;
        uint k3 = 0;
        uint k4 = 0;

        final switch (data.length & 15)
        {
        case 15:
            k4 ^= data[14] << 16;
            goto case;
        case 14:
            k4 ^= data[13] << 8;
            goto case;
        case 13:
            k4 ^= data[12] << 0;
            h4 ^= shuffle(k4, c4, c1, 18);
            goto case;
        case 12:
            k3 ^= data[11] << 24;
            goto case;
        case 11:
            k3 ^= data[10] << 16;
            goto case;
        case 10:
            k3 ^= data[9] << 8;
            goto case;
        case 9:
            k3 ^= data[8] << 0;
            h3 ^= shuffle(k3, c3, c4, 17);
            goto case;
        case 8:
            k2 ^= data[7] << 24;
            goto case;
        case 7:
            k2 ^= data[6] << 16;
            goto case;
        case 6:
            k2 ^= data[5] << 8;
            goto case;
        case 5:
            k2 ^= data[4] << 0;
            h2 ^= shuffle(k2, c2, c3, 16);
            goto case;
        case 4:
            k1 ^= data[3] << 24;
            goto case;
        case 3:
            k1 ^= data[2] << 16;
            goto case;
        case 2:
            k1 ^= data[1] << 8;
            goto case;
        case 1:
            k1 ^= data[0] << 0;
            h1 ^= shuffle(k1, c1, c2, 15);
            goto case;
        case 0:
        }
    }

    /// Incorporate size and finalizes the hash.
    void finalize() pure nothrow @nogc
    {
        h1 ^= size;
        h2 ^= size;
        h3 ^= size;
        h4 ^= size;

        h1 += h2;
        h1 += h3;
        h1 += h4;
        h2 += h1;
        h3 += h1;
        h4 += h1;

        h1 = fmix(h1);
        h2 = fmix(h2);
        h3 = fmix(h3);
        h4 = fmix(h4);

        h1 += h2;
        h1 += h3;
        h1 += h4;
        h2 += h1;
        h3 += h1;
        h4 += h1;
    }

    /// Returns the hash as an uint[4] value.
    Block get() pure nothrow @nogc
    {
        return [h1, h2, h3, h4];
    }
}

unittest
{
    checkResult!SMurmurHash3_x86_128([
        "" : "00000000000000000000000000000000",
        "a" : "3C9394A71BB056551BB056551BB05655",
        "ab" : "DF5184151030BE251030BE251030BE25",
        "abc" : "D1C6CD75A506B0A2A506B0A2A506B0A2",
        "abcd" : "AACCB6962EC6AF452EC6AF452EC6AF45",
        "abcde" : "FB2E40C5BCC5245D7701725A7701725A",
        "abcdef" : "0AB97CE12127AFA1F9DFBEA9F9DFBEA9",
        "abcdefg" : "D941B590DE3A86092869774A2869774A",
        "abcdefgh" : "3611F4AE8714B1AD92806CFA92806CFA",
        "abcdefghi" : "1C8C05AD6F590622107DD2147C4194DD",
        "abcdefghij" : "A72ED9F50E90379A2AAA92C77FF12F69",
        "abcdefghijk" : "DDC9C8A01E111FCA2DF1FE8257975EBD",
        "abcdefghijkl" : "FE038573C02482F4ADDFD42753E58CD2",
        "abcdefghijklm" : "15A23AC1ECA1AEDB66351CF470DE2CD9",
        "abcdefghijklmn" : "8E11EC75D71F5D60F4456F944D89D4F1",
        "abcdefghijklmno" : "691D6DEEAED51A4A5714CE84A861A7AD",
        "abcdefghijklmnop" : "2776D29F5612B990218BCEE445BA93D1",
        "abcdefghijklmnopq" : "D3A445046F5C51642ADC6DD99D07111D",
        "abcdefghijklmnopqr" : "AA5493A0DA291D966A9E7128585841D9",
        "abcdefghijklmnopqrs" : "281B6A4F9C45B9BFC3B77850930F2C20",
        "abcdefghijklmnopqrst" : "19342546A8216DB62873B49E545DCB1F",
        "abcdefghijklmnopqrstu" : "A6C0F30D6C738620E7B9590D2E088D99",
        "abcdefghijklmnopqrstuv" : "A7D421D9095CDCEA393CBBA908342384",
        "abcdefghijklmnopqrstuvw" : "C3A93D572B014949317BAD7EE809158F",
        "abcdefghijklmnopqrstuvwx" : "802381D77956833791F87149326E4801",
        "abcdefghijklmnopqrstuvwxy" : "0AC619A5302315755A80D74ADEFAA842",
        "abcdefghijklmnopqrstuvwxyz" : "1306343E662F6F666E56F6172C3DE344"]);
}

/**
MurmurHash3 for x86_64 processors producing a 128 bits value.

This is a lower level implementation that makes finalization optional and have slightly better performance.
Note that $(D putRemainder) can be called only once and that no subsequent calls to $(D putBlocks) is allowed.
*/
struct SMurmurHash3_x64_128
{
private:
    enum ulong c1 = 0x87c37b91114253d5;
    enum ulong c2 = 0x4cf5ad432745937f;
    ulong h2, h1;

public:
    alias Block = ulong[2]; /// The element size for x64_128 implementation.
    size_t size;

    this(ulong seed)
    {
        h2 = h1 = seed;
    }

    this(ulong seed2, ulong seed1)
    {
        h2 = seed2;
        h1 = seed1;
    }

    @disable this(this);

    /// Adds a single Block of data without increasing size.
    /// Make sure to increase size by Block.sizeof for each call to putBlock.
    void putBlock(Block block) pure nothrow @nogc
    {
        update(h1, block[0], h2, c1, c2, 31, 27, 0x52dce729);
        update(h2, block[1], h1, c2, c1, 33, 31, 0x38495ab5);
    }

    /// Put remainder bytes. This must be called only once after putBlock and before finalize.
    void putRemainder(scope const(ubyte[]) data...) pure nothrow @nogc
    {
        assert(data.length < Block.sizeof);
        assert(data.length >= 0);
        size += data.length;
        ulong k1 = 0;
        ulong k2 = 0;
        final switch (data.length & 15)
        {
        case 15:
            k2 ^= ulong(data[14]) << 48;
            goto case;
        case 14:
            k2 ^= ulong(data[13]) << 40;
            goto case;
        case 13:
            k2 ^= ulong(data[12]) << 32;
            goto case;
        case 12:
            k2 ^= ulong(data[11]) << 24;
            goto case;
        case 11:
            k2 ^= ulong(data[10]) << 16;
            goto case;
        case 10:
            k2 ^= ulong(data[9]) << 8;
            goto case;
        case 9:
            k2 ^= ulong(data[8]) << 0;
            h2 ^= shuffle(k2, c2, c1, 33);
            goto case;
        case 8:
            k1 ^= ulong(data[7]) << 56;
            goto case;
        case 7:
            k1 ^= ulong(data[6]) << 48;
            goto case;
        case 6:
            k1 ^= ulong(data[5]) << 40;
            goto case;
        case 5:
            k1 ^= ulong(data[4]) << 32;
            goto case;
        case 4:
            k1 ^= ulong(data[3]) << 24;
            goto case;
        case 3:
            k1 ^= ulong(data[2]) << 16;
            goto case;
        case 2:
            k1 ^= ulong(data[1]) << 8;
            goto case;
        case 1:
            k1 ^= ulong(data[0]) << 0;
            h1 ^= shuffle(k1, c1, c2, 31);
            goto case;
        case 0:
        }
    }

    /// Incorporate size and finalizes the hash.
    void finalize() pure nothrow @nogc
    {
        h1 ^= size;
        h2 ^= size;

        h1 += h2;
        h2 += h1;
        h1 = fmix(h1);
        h2 = fmix(h2);
        h1 += h2;
        h2 += h1;
    }

    /// Returns the hash as an ulong[2] value.
    Block get() pure nothrow @nogc
    {
        return [h1, h2];
    }
}

unittest
{
    checkResult!SMurmurHash3_x64_128([
        "" : "00000000000000000000000000000000",
        "a" : "897859F6655555855A890E51483AB5E6",
        "ab" : "2E1BED16EA118B93ADD4529B01A75EE6",
        "abc" : "6778AD3F3F3F96B4522DCA264174A23B",
        "abcd" : "4FCD5646D6B77BB875E87360883E00F2",
        "abcde" : "B8BB96F491D036208CECCF4BA0EEC7C5",
        "abcdef" : "55BFA3ACBF867DE45C842133990971B0",
        "abcdefg" : "99E49EC09F2FCDA6B6BB55B13AA23A1C",
        "abcdefgh" : "028CEF37B00A8ACCA14069EB600D8948",
        "abcdefghi" : "64793CF1CFC0470533E041B7F53DB579",
        "abcdefghij" : "998C2F770D5BC1B6C91A658CDC854DA2",
        "abcdefghijk" : "029D78DFB8D095A871E75A45E2317CBB",
        "abcdefghijkl" : "94E17AE6B19BF38E1C62FF7232309E1F",
        "abcdefghijklm" : "73FAC0A78D2848167FCCE70DFF7B652E",
        "abcdefghijklmn" : "E075C3F5A794D09124336AD2276009EE",
        "abcdefghijklmno" : "FB2F0C895124BE8A612A969C2D8C546A",
        "abcdefghijklmnop" : "23B74C22A33CCAC41AEB31B395D63343",
        "abcdefghijklmnopq" : "57A6BD887F746475E40D11A19D49DAEC",
        "abcdefghijklmnopqr" : "508A7F90EC8CF0776BC7005A29A8D471",
        "abcdefghijklmnopqrs" : "886D9EDE23BC901574946FB62A4D8AA6",
        "abcdefghijklmnopqrst" : "F1E237F926370B314BD016572AF40996",
        "abcdefghijklmnopqrstu" : "3CC9FF79E268D5C9FB3C9BE9C148CCD7",
        "abcdefghijklmnopqrstuv" : "56F8ABF430E388956DA9F4A8741FDB46",
        "abcdefghijklmnopqrstuvw" : "8E234F9DBA0A4840FFE9541CEBB7BE83",
        "abcdefghijklmnopqrstuvwx" : "F72CDED40F96946408F22153A3CF0F79",
        "abcdefghijklmnopqrstuvwxy" : "0F96072FA4CBE771DBBD9E398115EEED",
        "abcdefghijklmnopqrstuvwxyz" : "A94A6F517E9D9C7429D5A7B6899CADE9"]);
}

unittest
{
    // Pushing unaligned data and making sure the result is still coherent.
    void testUnalignedHash(H)()
    {
        immutable ubyte[1025] data = 0xAC;
        immutable alignedHash = digest!H(data[0 .. $ - 1]); // 0..1023
        immutable unalignedHash = digest!H(data[1 .. $]); // 1..1024
        assert(alignedHash == unalignedHash);
    }

    testUnalignedHash!MurmurHash3_x86_32();
    testUnalignedHash!MurmurHash3_x86_128();
    testUnalignedHash!MurmurHash3_x64_128();
}

//private:
/*
This is a helper struct and is not intended to be used directly. MurmurHash
cannot put chunks smaller than Block.sizeof at a time. This struct stores
remainder bytes in a buffer and pushes it when the block is complete or during
finalization.
*/
struct Piecewise(Hasher)
{
    enum blockSize = bits!Block;

    alias Block = Hasher.Block;
    union BufferUnion
    {
        Block block;
        ubyte[Block.sizeof] data;
    }

    BufferUnion buffer;
    size_t bufferSize;
    Hasher hasher;

    // Initialize
    void start()
    {
        this = Piecewise.init;
    }

    /**
    Adds data to the digester. This function can be called many times in a row
    after start but before finish.
    */
    void put(scope const(ubyte)[] data...) pure nothrow
    {
        // Buffer should never be full while entering this function.
        assert(bufferSize < Block.sizeof);

        // Check if we have some leftover data in the buffer. Then fill the first block buffer.
        if (bufferSize + data.length < Block.sizeof)
        {
            buffer.data[bufferSize .. bufferSize + data.length] = data[];
            bufferSize += data.length;
            return;
        }
        const bufferLeeway = Block.sizeof - bufferSize;
        assert(bufferLeeway <= Block.sizeof);
        buffer.data[bufferSize .. $] = data[0 .. bufferLeeway];
        hasher.putBlock(buffer.block);
        data = data[bufferLeeway .. $];

        // Do main work: process chunks of Block.sizeof bytes.
        const numBlocks = data.length / Block.sizeof;
        const remainderStart = numBlocks * Block.sizeof;
        version(NO_UNALIGNED_ACCESS) assert(data.ptr % Block.alignof == 0);
        foreach (const Block block; cast(const(Block[]))(data[0 .. remainderStart]))
        {
            hasher.putBlock(block);
        }
        // +1 for bufferLeeway Block.
        hasher.size += (numBlocks + 1) * Block.sizeof;
        data = data[remainderStart .. $];

        // Now add remaining data to buffer.
        assert(data.length < Block.sizeof);
        bufferSize = data.length;
        buffer.data[0 .. data.length] = data[];
    }

    /**
    Finalizes the computation of the hash and returns the computed value.
    Note that $(D finish) can be called only once and that no subsequent calls
    to $(D put) is allowed.
    */
    ubyte[Block.sizeof] finish() pure nothrow
    {
        auto tail = getRemainder();
        if (tail.length > 0)
        {
            hasher.putRemainder(tail);
        }
        hasher.finalize();
        return hasher.getBytes();
    }

private:
    const(ubyte)[] getRemainder()
    {
        return buffer.data[0 .. bufferSize];
    }
}

unittest
{
    struct DummyHasher
    {
        alias Block = ubyte[2];
        const(Block)[] results;
        size_t size;

        void putBlock(Block value) pure nothrow
        {
            results ~= value;
        }

        void putRemainder(scope const(ubyte)[] data...) pure nothrow
        {
        }

        void finalize() pure nothrow
        {
        }

        Block getBytes() pure nothrow
        {
            return Block.init;
        }
    }

    auto digester = Piecewise!DummyHasher();
    assert(digester.hasher.results == []);
    assert(digester.getRemainder() == []);
    digester.put(0);
    assert(digester.hasher.results == []);
    assert(digester.getRemainder() == [0]);
    digester.put(1, 2);
    assert(digester.hasher.results == [[0, 1]]);
    assert(digester.getRemainder() == [2]);
    digester.put(3, 4, 5);
    assert(digester.hasher.results == [[0, 1], [2, 3], [4, 5]]);
    assert(digester.getRemainder() == []);
}

template bits(T)
{
    enum bits = T.sizeof * 8;
}

T rotl(T)(T x, uint y)
in
{
    import std.traits : isUnsigned;

    static assert(isUnsigned!T);
    assert(y >= 0 && y <= bits!T);
}
body
{
    return ((x << y) | (x >> (bits!T - y)));
}

T shuffle(T)(T k, T c1, T c2, ubyte r1)
{
    import std.traits : isUnsigned;

    static assert(isUnsigned!T);
    k *= c1;
    k = rotl(k, r1);
    k *= c2;
    return k;
}

void update(T)(ref T h, T k, T mixWith, T c1, T c2, ubyte r1, ubyte r2, T n)
{
    import std.traits : isUnsigned;

    static assert(isUnsigned!T);
    h ^= shuffle(k, c1, c2, r1);
    h = rotl(h, r2);
    h += mixWith;
    h = h * 5 + n;
}

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
