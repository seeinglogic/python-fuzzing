import atheris

# Import target function
with atheris.instrument_imports():
    from target.evaluate import evaluate_expression


def get_input(data: bytes) -> str:
    """Create an input of the right type from the data"""
    fdp = atheris.FuzzedDataProvider(data)
    max_len = 20
    return fdp.ConsumeUnicodeNoSurrogates(max_len)


def TestOneInput(data: bytes) -> None:
    """Run an input through the target function"""

    expr = get_input(data)
    try:
        result = evaluate_expression(expr)
        assert isinstance(result, float)
    except ValueError as e:
        pass
    except ZeroDivisionError as e:
        pass

if __name__ == "__main__":
    import sys
    print(f'{sys.argv=}')
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()