# YATTO
**Yet Another Trip Time Optimizer**

_(still in development)_

This is a locally runnable web app that lets you optimize pedestrian, road, or bike trips in a few methods. Supposing we have three points, `A`, `B`, `C`:

- Vanilla TSP: `A -> B -> C -> A` (shortest cycle, up to a reordering, e.g. `C -> A -> B -> C` is equivalent)
- Shortest Path with Start Constraint (no end constraint): `A -> C -> B`
- Shortest Path with Constraints (start at A, end at C): `A -> B -> C`
- Shortest Path Overall (no start or end constraints): `C -> A -> B`

This optimization is done using Google Maps API and OR-Tools. You can save and edit trips for later.

This app is written as a personal full stack exercise, and should not be considered a very polished product.