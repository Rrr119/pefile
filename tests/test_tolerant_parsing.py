"""Regression tests for tolerant parsing and error classification."""

import random
import struct

import pytest

import pefile
from tests import PE_32, PE_64


def _make_malformed_samples(count=100):
    """Create a deterministic collection of malformed and truncated PEs."""
    rng = random.Random(38841)  # noqa: S311 - deterministic, non-cryptographic data
    samples = []
    valid_samples = (bytes(PE_32), bytes(PE_64))

    for index in range(count):
        base = valid_samples[index % len(valid_samples)]

        if index % 5 == 0:
            # Truncate at arbitrary positions, including the very beginning.
            position = rng.randrange(0, len(base))
            samples.append(base[:position])
        elif index % 5 == 1:
            # Damage header, directory and section bytes.
            sample = bytearray(base)
            for _ in range(rng.randint(1, 12)):
                position = rng.randrange(0, len(sample))
                sample[position] = rng.randrange(256)
            samples.append(bytes(sample))
        elif index % 5 == 2:
            # Completely arbitrary data of varying lengths.
            length = rng.randrange(0, 1024)
            samples.append(bytes(rng.randrange(256) for _ in range(length)))
        elif index % 5 == 3:
            # Valid headers with deliberately invalid numeric fields.
            sample = bytearray(base)
            e_lfanew = struct.unpack_from("<I", sample, 0x3C)[0]
            fields = (
                e_lfanew,
                e_lfanew + 6,
                e_lfanew + 4 + 16,
                e_lfanew + 4 + 20,
                e_lfanew + 4 + 20 + 32,
            )
            field = rng.choice(fields)
            value = rng.choice((0, 1, 0xFFFF, 0x7FFFFFFF, 0xFFFFFFFF))
            if field + 4 <= len(sample):
                struct.pack_into("<I", sample, field, value)
            samples.append(bytes(sample))
        else:
            # Randomly truncate and then mutate the remaining prefix.
            cut = rng.randrange(0, len(base))
            sample = bytearray(base[:cut])
            for _ in range(rng.randint(0, 5)):
                if sample:
                    position = rng.randrange(0, len(sample))
                    sample[position] = rng.randrange(256)
            samples.append(bytes(sample))

    return samples


def test_100_malformed_samples_never_crash():
    """Acceptance: 100 malformed samples parse without exceptions."""
    samples = _make_malformed_samples(100)
    results = pefile.parse_many(samples, fast_load=False)

    assert len(results) == 100
    assert all(result.parse_complete for result in results)

    for result in results:
        # Both dump helpers must remain safe on partially parsed instances.
        assert isinstance(result.dump_info(), str)
        assert isinstance(result.dump_dict(), dict)

    statistics = results.get_error_statistics()
    assert statistics["samples"] == 100
    assert statistics["total_errors"] == sum(
        len(result.get_parse_errors()) for result in results
    )
    assert results.error_stats


def test_partial_headers_are_returned_when_section_table_is_truncated():
    """Header fields parsed before the truncation remain available."""
    data = bytes(PE_32)
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    # Full optional header, but no section table or section contents.
    truncated = data[: e_lfanew + 4 + 20 + 96]

    result = pefile.PE(data=truncated, tolerant=True)

    assert result.DOS_HEADER is not None
    assert result.NT_HEADERS is not None
    assert result.FILE_HEADER is not None
    assert result.OPTIONAL_HEADER is not None
    assert isinstance(result.OPTIONAL_HEADER.DATA_DIRECTORY, list)
    assert isinstance(result.sections, list)


def test_strict_mode_and_classified_exceptions_are_compatible():
    """The default API still raises PEFormatError, with a category attached."""
    with pytest.raises(pefile.PEFormatError) as exception:
        pefile.PE(data=b"\0" * 64)
    assert exception.value.category == pefile.PEErrorCategory.DOS_HEADER

    # Tolerant parsing of the same bytes returns an object instead.
    result = pefile.PE(data=b"\0" * 64, tolerant=True)
    assert isinstance(result, pefile.PE)
    assert result.get_error_stats()[pefile.PEErrorCategory.DOS_HEADER] == 1


def test_valid_input_produces_identical_results_in_both_modes():
    """Tolerant mode must not change results for well-formed input."""
    for data in (PE_32, PE_64):
        strict = pefile.PE(data=bytes(data))
        tolerant = pefile.PE(data=bytes(data), tolerant=True)

        assert tolerant.parse_ok
        assert tolerant.get_parse_errors() == []
        assert strict.dump_info() == tolerant.dump_info()
        assert strict.dump_dict() == tolerant.dump_dict()


def test_error_statistics_are_grouped_by_category():
    """Each recorded issue contributes to exactly one category count."""
    samples = _make_malformed_samples(20)
    results = pefile.parse_many(samples, fast_load=False)

    by_category = results.get_error_stats("category")
    assert set(by_category) == set(results.error_stats)
    assert sum(by_category.values()) == results.total_errors
    assert results.get_error_stats("stage")
    assert results.get_error_stats("exception_type")
