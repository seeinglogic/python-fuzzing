# Getting Started with Python Fuzzing Using Atheris

The code in this directory accompanies the following post: https://seeinglogic.com/posts/intro-to-atheris/

It shows how to set up a very basic fuzz harness for a single function, more for demonstration than actual useful fuzzing.

The target in this case is AI-generated code that tries to evaluate arithmetic expressions given as a string, but other than the input and exception types the target is largely ignored.

However, the resulting [harness code](./eval_harness.py) serves as a good template, demonstrating:

- Proper instrumentation of the target
- Using `FuzzedDataProvider` to make an input of the correct type
- Catching expected exception types

You can test this by ensuring you have Atheris installed (`pip3 install atheris`), and then:

```bash
python3 eval_harness.py
```

This should kick off the fuzzing loop and you should see LibFuzzer-style output.
It is not expected to terminate on its own, so you'll have to stop it with CTRL+C.

This directory also includes a corpus evaluation [script](./run_corpus.py) for debugging or coverage purposes.
 
For more, see the associated [post](https://seeinglogic.com/posts/intro-to-atheris/).
