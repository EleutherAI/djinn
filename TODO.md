### TODO

1. Improve prompt to ensure insecure validation matches described vulnerability
2. Implement post-generation LLM check to ensure validation/exploit example matches described vulnerability
3. Add a compliant example to the prompt when testing whether models can solve the problem
4. Do some prompt optimization to improve compliance when asking for code that exploits vulnerabilities
5. Add some suggestions for leaking validator information in the prompt, e.g.
  - Input assumptions mimicing Leetcode's style (but omitting important cases)
  - Fake shell commands exploring files in repo
  - Validator snippet to help produce code with correct signature
6. Ensure that, when sampling primeintellect (or other dataset), we actually pick different problems each time