"""find_days must stay fast on long, crafted input (code scanning alert #1).

The old pattern r"(\d+)\s*days?" tries every digit as a starting point and
backtracks from each one, so a long run of digits takes quadratic time.
The API caps questions at 500 characters, but the helper should be safe on
its own.
"""
import time

from app import ask

LIMIT_SECONDS = 0.5


def timed(question):
    start = time.perf_counter()
    result = ask.find_days(question)
    return result, time.perf_counter() - start


# Same answers as before the fix

def test_reads_days():
    assert ask.find_days("not scanned in the last 45 days") == 45


def test_reads_one_day():
    assert ask.find_days("anything new in 1 day") == 1


def test_no_space_before_days():
    assert ask.find_days("stale for 90days") == 90


def test_skips_numbers_that_are_not_days():
    assert ask.find_days("2 hosts not scanned in 60 days") == 60


def test_no_number_uses_default():
    assert ask.find_days("stale scans") == 30
    assert ask.find_days("stale scans", default=7) == 7


# Fast on crafted input

def test_long_run_of_digits_is_fast():
    result, seconds = timed("1" * 20000 + "x")
    assert result == 30
    assert seconds < LIMIT_SECONDS


def test_digits_separated_by_spaces_is_fast():
    result, seconds = timed("1 " * 10000 + "x")
    assert result == 30
    assert seconds < LIMIT_SECONDS


def test_long_run_of_spaces_is_fast():
    result, seconds = timed("1" + " " * 20000 + "x")
    assert result == 30
    assert seconds < LIMIT_SECONDS
