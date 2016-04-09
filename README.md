# Probabilistic Linear Counting for Dlang

```D
auto counter = LPCounter(32); // 32 kilobytes for internal BitArray

/// loop
  counter.put(anArrayOrString);
  // or
  //counter.put(anUint);
  //counter.put(anUlong); // not that the 3 and 3L is different entities!
  //counter.put(anUUID);

size_t count = counter.count;
```

### building the example:

`dub build -c example`

then generate a random file with newlines:

`< /dev/urandom tr -dc "\t\n [:alnum:]" | head -n 100000 | ./lincount 128`

or just

`cat /some/file | sort | uniq | ./lincount`

## Licence:
www.boost.org/LICENSE_1_0.txt, Boost License 1.0