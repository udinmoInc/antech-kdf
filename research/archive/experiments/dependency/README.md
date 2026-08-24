# Sequential Dependency Experiment Laboratory

Compares independent work loops against strict sequential dependency chains ($element[i] = f(element[i-1])$).

## Key Questions
- Does strict sequential dependency prevent instruction pipelining and parallel thread splitting?
- What is the latency and throughput penalty on CPU vs simulated parallel GPU execution?
