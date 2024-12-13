# Fuzzing Python for Correctness: Checking on ChatGPT

The code in this directory accompanies the following post: https://seeinglogic.com/posts/checking-on-chatgpt/

It shows how to take the basic harness from the previous post and implement fuzzing for correctness via property testing and differential fuzzing.

The target in this case is AI-generated code that tries to evaluate arithmetic expressions given as a string.

The [final harness](./final_harness.py) is slightly customized for the target, but with small modifications can fuzz other functions that implement the same kind of functionality.

To run this, ensure you have Atheris installed (`pip3 install atheris`), and then:

```bash
python3 final_harness.py
```

This should kick off the fuzzing loop, and you should see differential fuzzing detect an issue within a second or two and save a crashing input to disk.

For more, see the associated [post](https://seeinglogic.com/posts/checking-on-chatgpt/).
