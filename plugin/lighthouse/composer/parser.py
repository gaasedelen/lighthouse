import re
import string
import operator

#------------------------------------------------------------------------------
# Text Tokens
#------------------------------------------------------------------------------

class TextToken(object):
    """
    A single tokenized text element.

    TextTokens are effectively wrappers for individual regex matches found
    when tokenizing a text string (eg, a composition string). They provide
    location and type information for the token as it exists in the string.

    Besides being used to normalize and guide the parsing of a given
    string, TextTokens can be used for things like syntax highlighting.
    """

    def __init__(self, match):
        self.type  = match.lastgroup
        self.value = (str(match.group())).upper()
        self.span  = match.span()

    @property
    def index(self):
        return self.span[0]

#
# COVERAGE_TOKEN:
#   'A' | 'B' | 'C' | ... | 'Z'
#

# NOTE: this is now dynamically computed in parse(...)
#COVERAGE_TOKEN = r'(?P<COVERAGE_TOKEN>[A-Za-z])'

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
UNKNOWN = r'(?P<UNKNOWN>.)'

TOKEN_DEFINITIONS = [OR, XOR, AND, MINUS, LPAREN, RPAREN, COMMA, WS, UNKNOWN]

#------------------------------------------------------------------------------
# AST Tokens
#------------------------------------------------------------------------------

class AstToken(object):
    """
    Base class for Abstract Syntax Tree (AST) Tokens.

    The Tokens subclassed from AstToken are used to build an abstract
    syntax tree representing a composition equation.

    Once generated, an AST can be logically evaluated by Lighthouse's
    director to compose a new coverage set described by the tree.
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

    eg: '|'
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

    eg: 'A,Z'
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

    eg: 'A'
    """

    def __init__(self, coverage_single):
        super(TokenCoverageSingle, self).__init__()
        self.text_tokens = [coverage_single]

        # referenced coverage set
        self.symbol = coverage_single.value

#------------------------------------------------------------------------------
# AST Operations
#------------------------------------------------------------------------------

def ast_equal(first, second):
    """
    A fail-safe equality of the structure and contents of two AST.

    This is not a true (logical) equality check. Two AST's may evaluate to
    the same logical result, but have a slightly different structure which
    will trigger this check to return False.

    This is primarily used to check if a user specified AST has changed, and
    if we should probably re-evaluate the tree (composition).
    """

    # both trees are 'NULL' / empty AST
    if isinstance(first, TokenNull) and isinstance(second, TokenNull):
        return True

    # recursively evaluate the AST's
    return _ast_equal_recursive(first, second)

def _ast_equal_recursive(first, second):
    """
    The internal (recursive) AST evaluation routine.
    """

    #
    # if the left and right types are not identical at every step, the tree
    # is obviously different somehow
    #

    if type(first) != type(second):
        return False

    #
    # if the current node is a logic operator, we need to evaluate the
    # expressions that make up its input.
    #

    if isinstance(first, TokenLogicOperator):
        if not _ast_equal_recursive(first.op1, second.op1):
            return False
        if not _ast_equal_recursive(first.op2, second.op2):
            return False
        return first.operator == second.operator

    #
    # if the current node is a coverage range, we need to evaluate the
    # range expression. this will produce an aggregate coverage set
    # described by the start/end of the range (Eg, 'A,D')
    #

    elif isinstance(first, TokenCoverageRange):
        return first.symbol_start == second.symbol_start and \
               first.symbol_end   == second.symbol_end

    #
    # if the current node is a coverage token, we need simply need
    # to compare its symbol.
    #

    elif isinstance(first, TokenCoverageSingle):
        return first.symbol == second.symbol

    #
    # unknown token? (this should never happen)
    #

    raise False

#------------------------------------------------------------------------------
# Parsing
#------------------------------------------------------------------------------

class ParseError(SyntaxError):
    """
    Exception raised when composition parsing fails.

    A ParseError will provide some contextual information to how and why
    the parser failed. Information gleaned through the exception can still
    be consumed for user hints, syntax highlighting, or other uses.
    """

    def __init__(self, message, expected, error_token, parsed_tokens):
        super(ParseError, self).__init__(message)
        self.expected = expected
        self.error_token = error_token
        self.parsed_tokens = parsed_tokens

        if error_token == self.parsed_tokens[-1]:
            fail = self.parsed_tokens.pop()
            self.error_index = fail.span[0]
        else:
            self.error_index = self.parsed_tokens[-1].span[1]

    def __str__(self):
        return "%s: at %s, %s" % (self.__class__.__name__, self.error_token.span, self.msg)

#------------------------------------------------------------------------------
# Composition Parser
#------------------------------------------------------------------------------

class CompositionParser(object):
    """
    A simple recursive descent parser for Compositions.

    Heavily modified from:
      https://rockie-yang.gitbooks.io/python-cookbook/content/ch2/simple_parser.html

    #----------------------------------------------------------------------

    Below is the spec for the LL(1) 'Composition Grammar' that was designed
    to generically parse coverage composition equations form raw text.

    #----------------------------------------------------------------------

    COMPOSITION:
        EXPRESSION COMPOSITION_TAIL

    COMPOSITION_TAIL:
        LOGIC_TOKEN COMPOSITION | None

    EXPRESSION:
        '(' EXPRESSION ')' COMPOSITION_TAIL | COVERAGE COMPOSITION_TAIL

    COVERAGE:
        COVERAGE_TOKEN COVERAGE_RANGE

    COVERAGE_RANGE:
        ',' COVERAGE_TOKEN | None

    COVERAGE_TOKEN:
        'A' | 'B' | 'C' | ... | 'Z'

    LOGIC_TOKEN:
        '&' | '|' | '^' | '-'

    """

    def parse(self, text, coverage_tokens):
        """
        Parse a string using the Composition Grammar.

        Returns an Abstract Syntax Tree (AST) of the parsed input.

        Raises ParseError on parse failure.
        """

        # if the string is *only* whitespace, return an empty, but valid parse
        if not text.strip():
            return ([], TokenNull())

        #
        # we used to parse [A-Za-z] as the COVERAGE_TOKEN, but that means we
        # would technically tokenize and construct trees with COVERAGE_TOKEN's
        # that have no matching (eg invalid) loaded coverage data.
        #
        # now we construct the COVERAGE_TOKEN regex just before parsing.
        # this enables us to tokenize/parse only the shorthand names that
        # reflect the state of loaded coverage
        #

        COVERAGE_TOKEN = r'(?P<COVERAGE_TOKEN>[%s])' % ''.join(coverage_tokens)

        #
        # if there were any coverage tokens defined, then we definitely need
        # the constructed COVERAGE_TOKEN regex in our grammar list.
        #

        if coverage_tokens:
            TOKEN_REGEXES = [COVERAGE_TOKEN] + TOKEN_DEFINITIONS
        else:
            TOKEN_REGEXES = TOKEN_DEFINITIONS

        # build our master tokenizer regex pattern to parse the text stream
        master_pattern = re.compile('|'.join(TOKEN_REGEXES))

        # reset the parser's runtime variables
        self._parsed_tokens = []
        self.current_token  = None
        self.next_token     = None

        # tokenize the raw text stream
        self.tokens = self._generate_tokens(master_pattern, text)

        # initialize the parser state by bumping the parser onto the first token
        self._advance()

        # parse the token stream using the grammar defined by this class
        ast = self._COMPOSITION()

        # if there are any tokens remaining in the stream, the text is invalid
        if self.next_token:
            self._parse_error("Expected $$", TokenNull)

        # return the parsed tokens and generated AST
        return (self._parsed_tokens, ast)

    #--------------------------------------------------------------------------
    # Token Stream Operations
    #--------------------------------------------------------------------------

    def _advance(self):
        """
        Advance one token in the token stream.
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

    def _generate_tokens(self, regex_pattern, text):
        """
        Generate a TextToken stream using a given regex token pattern and text.
        """
        scanner = regex_pattern.scanner(text)
        for m in iter(scanner.match, None):
            token = TextToken(m)
            self._parsed_tokens.append(token)
            if token.type != 'WS': # ignore whitespace tokens
                yield token

    def _parse_error(self, message, expected):
        """
        Raises a ParseError, capturing elements of the parser state.
        """
        raise ParseError(message, expected, self.next_token, self._parsed_tokens)

    #--------------------------------------------------------------------------
    # Grammar Rules
    #--------------------------------------------------------------------------

    def _COMPOSITION(self):
        """
        COMPOSITION:
            EXPRESSION COMPOSITION_TAIL
        """
        expression = self._EXPRESSION()
        return self._COMPOSITION_TAIL(expression)

    def _COMPOSITION_TAIL(self, head):
        """
        COMPOSITION_TAIL:
            LOGIC_TOKEN COMPOSITION | None
        """

        #
        # LOGIC_TOKEN COMPOSITION
        #

        logic_op = self._LOGIC_TOKEN()
        if logic_op:
            composition = self._COMPOSITION()
            return TokenLogicOperator(logic_op, head, composition)

        #
        # None
        #

        # no COMPOSITION_TAIL to parse, simply return the leading expression
        return head

    def _EXPRESSION(self):
        """
        EXPRESSION:
            '(' EXPRESSION ')' COMPOSITION_TAIL | COVERAGE COMPOSITION_TAIL
        """

        #
        # ['(' EXPRESSION ')'] COMPOSITION_TAIL
        #

        if self._accept('LPAREN'):

            # parse left paren
            left_paren = self.current_token

            # parse the expression
            expression = self._EXPRESSION() # THESE ARE CHILDREN

            # parse the right paren
            if not self._accept('RPAREN'):
                self._parse_error("Expected RPAREN", TextToken)
            right_paren = self.current_token

            # inject parenthesis TextTokens into the expression
            expression.text_tokens.append(left_paren)
            expression.text_tokens.append(right_paren)

        #
        # [COVERAGE] COMPOSITION_TAIL
        #

        else:
            expression = self._COVERAGE()

        # ... [COMPOSITION_TAIL]
        return self._COMPOSITION_TAIL(expression)

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
        self._parse_error("Expected COVERAGE_TOKEN", TokenCoverageSingle)

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
