# Generated by ChatGPT's o1-preview model, Sep 2024
#
# """Write a Python function that takes a mathematical expression as a string
# evaluates it. The function should handle basic arithmetic operators and
# precedence but does not need to handle parentheses. The function must not use
# Python’s eval function."""


def evaluate_expression(expr: str) -> float:

    def tokenize(expr):
        tokens = []
        i = 0
        prev_token = None
        while i < len(expr):
            c = expr[i]
            if c == ' ':
                i += 1
                continue
            if c in '+-*/':
                if c == '-' and (prev_token is None or prev_token in '+-*/'):
                    # Unary minus
                    i += 1
                    num = ''
                    while i < len(expr) and (expr[i].isdigit() or expr[i] == '.'):
                        num += expr[i]
                        i += 1
                    if num == '':
                        raise ValueError("Invalid syntax")
                    tokens.append('-' + num)
                    prev_token = 'number'
                else:
                    tokens.append(c)
                    prev_token = c
                    i += 1
            elif c.isdigit() or c == '.':
                num = c
                i += 1
                while i < len(expr) and (expr[i].isdigit() or expr[i] == '.'):
                    num += expr[i]
                    i +=1
                tokens.append(num)
                prev_token = 'number'
            else:
                raise ValueError(f"Invalid character: {c}")
        return tokens

    def shunting_yard(tokens):
        output_queue = []
        operator_stack = []
        precedence = {'+':1, '-':1, '*':2, '/':2}
        for token in tokens:
            if token.replace('.', '', 1).replace('-', '', 1).isdigit():
                output_queue.append(token)
            elif token in '+-*/':
                while (operator_stack and operator_stack[-1] in '+-*/' and
                       precedence[operator_stack[-1]] >= precedence[token]):
                    output_queue.append(operator_stack.pop())
                operator_stack.append(token)
            else:
                raise ValueError(f"Invalid token: {token}")
        while operator_stack:
            output_queue.append(operator_stack.pop())
        return output_queue

    def evaluate_rpn(tokens):
        stack = []
        for token in tokens:
            if token.replace('.', '', 1).replace('-', '', 1).isdigit():
                stack.append(float(token))
            elif token in '+-*/':
                if len(stack) < 2:
                    raise ValueError("Invalid syntax")
                b = stack.pop()
                a = stack.pop()
                if token == '+':
                    stack.append(a+b)
                elif token == '-':
                    stack.append(a-b)
                elif token == '*':
                    stack.append(a*b)
                elif token == '/':
                    stack.append(a/b)
            else:
                raise ValueError(f"Invalid token in RPN: {token}")
        if len(stack) != 1:
            raise ValueError("Invalid syntax")
        return stack[0]

    tokens = tokenize(expr)
    rpn = shunting_yard(tokens)
    result = evaluate_rpn(rpn)
    return result
