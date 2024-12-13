import atheris
import os
import sys

from target.evaluate import evaluate_expression


def get_input(data: bytes) -> str:
    """Create an input of the right type from the data"""
    fdp = atheris.FuzzedDataProvider(data)
    max_len = 20
    return fdp.ConsumeUnicodeNoSurrogates(max_len)


def RunInputFromFile(file_path: str):
    with open(file_path, 'rb') as f:
        data = f.read()

    expr = get_input(data)
    try:
        result = evaluate_expression(expr)
    except ValueError:
        pass
    except ZeroDivisionError:
        pass



def main(corpus: str):

    if os.path.isdir(corpus):
        for filename in os.listdir(corpus):
            file_path = os.path.join(corpus, filename)
            RunInputFromFile(file_path)
        print(f'[*] Ran {len(os.listdir(corpus))} inputs from "{corpus}"')

    elif os.path.isfile(corpus):
        one_file = corpus
        RunInputFromFile(one_file)
        print(f'[*] Ran single input "{one_file}"')


if __name__ == "__main__":

    if len(sys.argv) != 2:
        print("USAGE: python run_corpus.py CORPUS")
        exit(-1)

    corpus = sys.argv[1]
    main(corpus)