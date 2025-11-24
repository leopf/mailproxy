import re
from typing import Callable, TypeVar, Protocol, TypeVarTuple, Unpack

Ts = TypeVarTuple("Ts")
T = TypeVar("T", covariant=True)
U = TypeVar("U", covariant=True)

class Parser(Protocol[T]):
  def __call__(self, s: str) -> tuple[T, str]: ...

class TryParseError(Exception):
  def __init__(self, message: str, remainder: str) -> None:
    super().__init__(f"Parser failed with message '{message}' at -{len(remainder)}")
    self.message = message
    self.back_offset = len(remainder)

class ParserError(Exception):
  pass

def const(c: str) -> Parser[str]:
  def _inner(s: str):
    if s[:len(c)] == c:
      return c, s[len(c):]
    else:
      raise TryParseError(f"failed to parse '{c}'", s)
  return _inner

def regex(pattern: str, flags: int = 0) -> Parser[re.Match]:
  matcher = re.compile(pattern, flags)
  def _inner(s: str):
    match = matcher.match(s)
    if match is None:
      raise TryParseError(f"failed to parse '{pattern}'", s)
    return match, s[match.endpos]
  return _inner

def transform(parser: Parser[T], transformer: Callable[[T], U]) -> Parser[U]:
  def _inner(s: str):
    result, remainder = parser(s)
    return transformer(result), remainder
  return _inner

def alt(*args: Parser[T]) -> Parser[T]:
  def _inner(s: str):
    for p in args:
      try:
        return p(s)
      except TryParseError:
        pass
    raise TryParseError(f"no alt matched", s)
  return _inner

def seq(*args: Parser[T]) -> Parser[tuple[T, ...]]:
  def _inner(s: str):
    results: list[T] = []
    remainder = s
    for p in args:
      result, remainder = p(remainder)
      results.append(result)
    return tuple(results), remainder
  return _inner

def parse(s: str, parser: Parser[T]) -> T:
  try:
    result, remainder = parser(s)
  except TryParseError as e:
    raise ParserError(f"Failed to parse string: {e}\n" + s[:-e.back_offset] + "<FAILED HERE>" + s[-e.back_offset:])

  if len(remainder) > 0:
    raise ParserError("Failed to parse entire str")
  return result