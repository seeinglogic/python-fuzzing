#!/usr/bin/env python3

# eval_harness.py
import atheris
import re
import string

# Import target function
with atheris.instrument_imports():
    from target.evaluate import evaluate_expression



def get_input(data: bytes) -> str:
    """Create an input of the right type from the data"""

    fdp = atheris.FuzzedDataProvider(data)
    max_len = 20

    # Don't return something longer than the input data itself
    effective_len = min(len(data), max_len)

    ALLOWED_CHARACTERS = list(string.digits + '.' + ' ' + '+-*/')

    output = ''
    for _ in range(effective_len):
        output += fdp.PickValueInList(ALLOWED_CHARACTERS)

    return output


def is_malformed_expression(s: str) -> bool:
    """Property test: expressions have `number [operator number]` format
    
    NOTE: this is incomplete, but differential fuzzing helps fill the gap
    """

    cur_number = ''

    number_contains_dot = False
    leading_dash = False
    operators = '+-*/'

    s = s.replace(' ', '')
    # If the expression only contained whitespace, that's invalid
    if s == '':
        return True

    for i, c in enumerate(s):
        # Allow looking ahead one, except last_char
        if i == len(s) - 1:
            next_char = None
            # expressions can't end in an operator
            if c in operators:
                return True
        else:
            next_char = s[i+1]

        # handle input
        if c == ' ':
            leading_dash = False

        elif c.isdigit():
            cur_number += c
            leading_dash = False

        elif c == '.':
            leading_dash = False
            # Can't contain two dots
            if number_contains_dot:
                return True
            else:
                # A number may lead with a dot...
                if cur_number == '':
                    # But digits must follow, can't just be a dot
                    if next_char is None or next_char in operators:
                        return True
                cur_number += '.'
                number_contains_dot = True

        elif c in operators:

            # expressions can't end with an operator
            if next_char is None:
                return True

            # expression may only start with a dash
            if i == 0:
                if c == '-':
                    # Number must follow
                    if next_char in operators:
                        return True
                else:
                    return True

            # if we are dash after an operator, the next char must not be an operator
            elif leading_dash:
                if next_char in operators:
                    return True
                leading_dash = False

            # Other than leading dash, Operator must have been preceded by a number
            elif leading_dash is False and cur_number == '':
                return True
            #
            # we are an operator following a number
            else:
                # a single dash can follow
                if next_char == '-':
                    leading_dash = True

            # operator resets what the cur number is
            cur_number = ''
            number_contains_dot = False

    return False


def remove_leading_zeroes(s: str) -> str:
    """Strip the leading zeroes from a string"""

    def repl(match):
        number = match.group(0)
        if re.match(r'\-?(0\.)\d+|\-?\.\d+', number):
            return number
        else:
            sign = '-' if number.startswith('-') else ''
            number = number.lstrip('-').lstrip('0') or '0'
            return sign + number

    return re.sub(r'\-?\d+(\.\d+)?|\-?\.\d+', repl, s)


def TestOneInput(data: bytes) -> None:
    """Run an input through the target function"""

    # Step 1: Get an input for the target
    expr = get_input(data)

    # Step 2: Calculate correctness properties for expressions
    prop_is_empty = expr == ''
    if prop_is_empty:
        # Don't waste time with empty expressions
        return

    prop_bad_expr = is_malformed_expression(expr)

    try:
        # Step 3: Send to target function
        result = evaluate_expression(expr)

        # Step 4A: Target function returned a result - check result & properties

        # type check the result
        if isinstance(result, float) is False:
            raise Exception(f'Result is not a float?! {expr=}, {result=} ({type(result)=})')

        # Correctness checks: no exception thrown, should one have been?
        if prop_is_empty is True:
            raise Exception(f'Empty Expression: Should have thrown a ValueError: {expr=}, {result=}')
        if prop_bad_expr is True:
            # The current is_malformed_expression implementation is imperfect
            # we'll rely on differential fuzzing instead
            if ' ' in expr:
                #print(f'RPN: Should have thrown a ValueError due to invalid expression: {expr=}, {result=}')
                pass
            else:
                raise Exception(f'Invalid Expression: Should have thrown a ValueError: {expr=}, {result=}')

        # Step 5: Differential fuzzing - check value's correctness against eval
        try:
            # Eval doesn't like leading zeroes
            trimmed_expr = remove_leading_zeroes(expr)
            eval_result = eval(trimmed_expr)

            # cast both results to float for apples-to-apples comparison
            result_cast = float(result)
            eval_result_cast = float(eval_result)

            if result_cast != eval_result_cast:
                # Define a threshold for acceptable floating point difference
                EPSILON = 0.00000000000001  # 1e-14
                difference = abs(eval_result_cast - result_cast)

                # Accept really small differences
                if difference < EPSILON:
                    pass
                # Accept really small differences (compared to input number)
                elif (difference / result_cast) < EPSILON:
                    pass
                # Larger differences indicate a math error
                else:
                    raise Exception(f'Math mismatch for {expr=}: {result_cast} != {eval_result_cast} ({result=} vs {eval_result=})')
        except SyntaxError as e:
            # This is where differential fuzzing catches RPN issues
            # If you comment the line below, fuzzing should go forever
            raise Exception(f'eval() SyntaxError on {expr=} ({trimmed_expr=}), exception: {e} ({type(e)}), {result=}')
            pass  # For proceeding with testing


    # Step 4B: Target function threw an exception - check result & properties
    except ValueError as exception:
        # Correctness checks: an exception is expected if a property check fails
        if prop_is_empty is False and prop_bad_expr is False:
                # The current is_malformed_expression implementation is imperfect
                # we'll rely on differential fuzzing instead
                if ' ' in expr:
                    #print(f'Exception likely due to RPN, malformed expression check needs work: {expr=}, {result=}')
                    pass
                else:
                    raise Exception(f"Threw an exception for unexpected reasons: {expr=}, {exception=}")

    except ZeroDivisionError as e:
        pass


if __name__ == "__main__":
    import sys
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()
