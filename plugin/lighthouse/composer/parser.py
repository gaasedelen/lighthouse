import re
import string
import operator

#--------------------------------------------------------------------------
# Text Tokens
#--------------------------------------------------------------------------

#
# COVERAGE_TOKEN:
#   'A' | 'B' | 'C' | ... | 'Z'
#
# TODO: *
#

COVERAGE_TOKEN = r'(?P<COVERAGE_TOKEN>[A-Za-z])'

#
# LOGIC_TOKEN:
#   '|' | '^' | '&' | '-'
#

OR      = r'(?P<OR>\|)'
XOR     = r'(?P<XOR>\^)'
AND     = r'(?P<AND>\&)'
MINUS   = r'(?P<MINUS>-)'

#
# Misc Tokens
#

LPAREN  = r'(?P<LPAREN>\()'
RPAREN  = r'(?P<RPAREN>\))'
COMMA   = r'(?P<COMMA>\,)'
WS      = r'(?P<WS>\s+)'

master_pattern = re.compile(
    '|'.join((COVERAGE_TOKEN, OR, XOR, AND, MINUS, LPAREN, RPAREN, COMMA, WS))
)

class TextToken(object):
    """
    Text Token
    """
    def __init__(self, match):
        self.type  = match.lastgroup
        self.value = (str(match.group())).upper()
        self.span  = match.span()

    @property
    def index(self):
        return self.span[0]

def generate_tokens(pattern, text):
    scanner = pattern.scanner(text)
    for m in iter(scanner.match, None):
        token = TextToken(m)
        if token.type != 'WS':
            yield token

#--------------------------------------------------------------------------
# AST Tokens
#--------------------------------------------------------------------------

class AstToken(object):
    """
    Abstract Syntax Tree (AST) Token
    """

    def __init__(self):
        self.nodes = []
        self.text_tokens = []

class TokenNull(AstToken):
    """
    AST Token indicating a NULL / empty composition.
    """

    def __init__(self):
        super(TokenNull, self).__init__()

class TokenLogicOperator(AstToken):
    """
    AST Token for a logical operator.
    """

    def __init__(self, logic_op, op1, op2=None):
        super(TokenLogicOperator, self).__init__()
        self.text_tokens = [logic_op]

        # logic operator
        self.operator = self.str2op(logic_op.value)

        # referenced operands
        self.op1 = op1
        self.op2 = op2

        # save the operand expressions as children
        self.nodes = [op1, op2]

    @staticmethod
    def str2op(op_char):
        if op_char == '|':
            return operator.or_
        if op_char == '&':
            return operator.and_
        if op_char == '^':
            return operator.xor
        if op_char == '-':
            return operator.sub
        raise ValueError("Unknown Operator")

class TokenCoverageRange(AstToken):
    """
    AST Token for a coverage range reference.

    Eg: 'A,Z'
    """

    def __init__(self, start, comma, end):
        super(TokenCoverageRange, self).__init__()
        self.text_tokens = [start, comma, end]

        # referenced coverage sets
        self.symbol_start = start.value.upper()
        self.symbol_end   = end.value.upper()

class TokenCoverageSingle(AstToken):
    """
    AST Token for a single coverage reference.

    Eg: 'A'
    """

    def __init__(self, coverage_single):
        super(TokenCoverageSingle, self).__init__()
        self.text_tokens = [coverage_single]

        # referenced coverage set
        self.symbol = coverage_single.value

#--------------------------------------------------------------------------
# Composing Input Parser
#--------------------------------------------------------------------------

class ComposingParser(object):
    """
    A simple recursive descent parser for Composing.

    Heavily modified from:
      https://rockie-yang.gitbooks.io/python-cookbook/content/ch2/simple_parser.html

    #----------------------------------------------------------------------

    Below is the spec for the LL(1) grammar that was designed to parse
    the ComposingShell input.

    #----------------------------------------------------------------------

    COMPOSITION:
        EXPRESSION COMPOSITION_TAIL

    COMPOSITION_TAIL:
        LOGIC_TOKEN COMPOSITION | None

    EXPRESSION:
        '(' EXPRESSION ')' COMPOSITION_TAIL | COVERAGE COMPOSITION_TAIL
        #'(' EXPRESSION ')' | COVERAGE COMPOSITION_TAIL

    COVERAGE:
        COVERAGE_TOKEN COVERAGE_RANGE

    COVERAGE_RANGE:
        ',' COVERAGE_TOKEN | None

    COVERAGE_TOKEN:
        'A' | 'B' | 'C' | ... | 'Z'

    LOGIC_TOKEN:
        '&' | '|' | '^' | '-'

    """

    def parse(self, text):
        """
        Parse a string using the Composition Grammar.

        Returns an Abstract Syntax Tree (AST) of the parsed input.

        Raises SyntaxError on parse failure.
        """

        if not text.strip():
            return TokenNull()

        # prepare the token stream for parsing
        self.tokens = generate_tokens(master_pattern, text)
        self.current_token = None
        self.next_token = None

        # roll us onto the first token in the token stream
        self._advance()

        # run the token stream through the defined grammar
        ast = self._COMPOSITION()

        # if there are any tokens remaining in the stream, the text is invalid
        if self.next_token:
            raise SyntaxError("Expected $$")

        # return the computed abstract syntax tree
        return ast

    #--------------------------------------------------------------------------
    # Token Stream Operations
    #--------------------------------------------------------------------------

    def _advance(self):
        """
        Advance one token in the tokenstream.
        """
        self.current_token, self.next_token = self.next_token, next(self.tokens, None)
    def _accept(self, token_type):
        """
        Match and accept the lookahead token.
        """
        if self.next_token and self.next_token.type == token_type:
            self._advance()
            return True
        else:
            return False

    def _expect(self, token_type):
        """
        Match and discard the lookahead token.
        """
        if not self._accept(token_type):
            raise SyntaxError('Expected ' + token_type)

    #--------------------------------------------------------------------------
    # Grammar Rules
    #--------------------------------------------------------------------------

    def _COMPOSITION(self):
        """
        COMPOSITION:
            EXPRESSION COMPOSITION_TAIL
        """

        expression = self._EXPRESSION()
        composition_tail = self._COMPOSITION_TAIL()

        if composition_tail:

            # unpack COMPOSITION := EXPRESSION [COMPOSITION_TAIL]
            logic_op, compisition = composition_tail

            # construct and build the logic op
            return TokenLogicOperator(logic_op, expression, compisition)

        #
        # the expression evaluated only to a coverage item
        #

        return expression

    def _COMPOSITION_TAIL(self):
        """
        COMPOSITION_TAIL:
            LOGIC_TOKEN COMPOSITION | None
        """

        #
        # LOGIC_TOKEN COMPOSITION
        #

        logic_op = self._LOGIC_TOKEN()
        if logic_op:
            return (logic_op, self._COMPOSITION())

        #
        # None
        #

        return None

    def _EXPRESSION(self):
        """
        EXPRESSION:
            '(' EXPRESSION ')' COMPOSITION_TAIL | COVERAGE COMPOSITION_TAIL
        """

        #
        # '(' EXPRESSION ')'
        #

        # parse left paren
        if self._accept('LPAREN'):
            left_paren = self.current_token

            # parse the expression
            expression = self._EXPRESSION() # THESE ARE CHILDREN

            # parse the right paren
            if not self._accept('RPAREN'):
                raise SyntaxError("Expected RPAREN")
            right_paren = self.current_token

            # inject parenthesesis TextTokens into the expression
            expression.text_tokens.append(left_paren)
            expression.text_tokens.append(right_paren)

            # TODO: condense
            compisition_tail = self._COMPOSITION_TAIL()
            if compisition_tail:
                logic_op, compisition = compisition_tail
                return TokenLogicOperator(logic_op, expression, compisition)

            # return the parsed expression
            return expression

        #
        # COVERAGE COMPOSITION_TAIL
        #

        coverage = self._COVERAGE()
        compisition_tail = self._COMPOSITION_TAIL()

        #
        # this case being true implies that there exists a composition
        # tail for this expression, eg a 'logic' op and something else
        #

        if compisition_tail:

            # unpack EXPRESION := COVERAGE [COMPOSITION_TAIL]
            logic_op, compisition = compisition_tail

            # construct and build the logic op
            return TokenLogicOperator(logic_op, coverage, compisition)

        #
        # the expression evaluated only to a coverage item
        #

        return coverage

    def _COVERAGE(self):
        """
        COVERAGE:
            COVERAGE_TOKEN COVERAGE_RANGE
        """
        coverage_start = self._COVERAGE_TOKEN()
        coverage_range = self._COVERAGE_RANGE()

        # if a there was a trailing ',A-Za-z' parsed, it's a coverage range
        if coverage_range:
            comma, coverage_end = coverage_range
            return TokenCoverageRange(coverage_start, comma, coverage_end)

        # return a single coverage set
        return TokenCoverageSingle(coverage_start)

    def _COVERAGE_RANGE(self):
        """
        COVERAGE_RANGE:
            ',' COVERAGE_TOKEN | None
        """
        if self._accept("COMMA"):
            return (self.current_token, self._COVERAGE_TOKEN())
        return None

    def _COVERAGE_TOKEN(self):
        """
        COVERAGE_TOKEN:
            'A' | 'B' | 'C' | ... | 'Z'
        """
        if self._accept("COVERAGE_TOKEN"):
            return self.current_token
        raise SyntaxError("Expected COVERAGE_TOKEN")

    def _LOGIC_TOKEN(self):
        """
        LOGIC_TOKEN:
            '&' | '|' | '^' | '-'
        """

        if self._accept("OR")  or \
           self._accept("XOR") or \
           self._accept("AND") or \
           self._accept("MINUS"):
            return self.current_token

        return None
