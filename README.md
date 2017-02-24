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

## Licence:
www.boost.org/LICENSE_1_0.txt, Boost License 1.0