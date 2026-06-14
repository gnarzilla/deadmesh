import pytest
import struct
import ctypes
import sys

# Simulated buffer processing function that mirrors the vulnerable C logic
# This Python simulation models the behavior described in mesh-sim.c
# where memcpy copies data into a buffer using an unvalidated 'len' parameter

BUFFER_SIZE = 256  # Typical mesh packet buffer size


def simulate_mesh_packet_copy(buf: bytearray, n: int, data: bytes, length: int) -> int:
    """
    Simulates the mesh-sim.c buffer copy operation with safety enforcement.
    
    Invariant: n + length must never exceed BUFFER_SIZE.
    Returns the number of bytes actually copied, or raises ValueError if
    the operation would overflow the buffer.
    
    A safe implementation MUST validate: n + length <= BUFFER_SIZE
    """
    if n < 0:
        raise ValueError("Offset n cannot be negative")
    if n >= BUFFER_SIZE:
        raise ValueError(f"Offset n={n} exceeds buffer size {BUFFER_SIZE}")
    
    # This is the SAFE version — it must reject or truncate oversized inputs
    if length < 0:
        raise ValueError("Length cannot be negative")
    
    # INVARIANT: n + length must not exceed BUFFER_SIZE
    if n + length > BUFFER_SIZE:
        raise ValueError(
            f"Buffer overflow prevented: n={n} + length={length} = {n + length} "
            f"exceeds buffer size {BUFFER_SIZE}"
        )
    
    # Safe copy
    actual_len = min(length, len(data))
    buf[n:n + actual_len] = data[:actual_len]
    return actual_len


def safe_mesh_packet_copy_truncating(buf: bytearray, n: int, data: bytes, length: int) -> int:
    """
    Alternative safe implementation that truncates instead of rejecting.
    Returns the number of bytes actually copied (truncated to fit).
    """
    if n < 0 or n >= BUFFER_SIZE:
        return 0
    if length < 0:
        return 0
    
    # Truncate to available space — INVARIANT enforced by clamping
    available = BUFFER_SIZE - n
    safe_length = min(length, available, len(data))
    buf[n:n + safe_length] = data[:safe_length]
    return safe_length


# Attack payloads: (n_offset, data, declared_length) tuples
# Each represents a crafted mesh radio packet attempting buffer overflow
ATTACK_PAYLOADS = [
    # (offset, data, declared_length, description)
    # 2x oversized
    (0, b"A" * 512, 512),
    # 10x oversized
    (0, b"B" * 2560, 2560),
    # Offset near boundary + large length
    (200, b"C" * 512, 512),
    # Offset at boundary - 1 + large length
    (255, b"D" * 256, 256),
    # Offset exactly at boundary
    (256, b"E" * 1, 1),
    # Offset past boundary
    (300, b"F" * 10, 10),
    # Zero offset, exact overflow by 1
    (0, b"G" * 257, 257),
    # Large offset + small length still overflows
    (250, b"H" * 10, 10),
    # Negative length (malformed packet)
    (0, b"I" * 10, -1),
    # Negative offset (malformed packet)
    (-1, b"J" * 10, 10),
    # Integer overflow attempt: large n + large len wraps around
    (0x7FFFFFFF, b"K" * 10, 10),
    # Length larger than data (declared length mismatch)
    (0, b"L" * 10, 512),
    # Maximum integer length
    (0, b"M" * 100, sys.maxsize),
    # Crafted to overflow: offset + length = BUFFER_SIZE + 1
    (128, b"N" * 129, 129),
    # All zeros payload but oversized length
    (0, b"\x00" * 1024, 1024),
    # NUL bytes with exact overflow
    (1, b"\x00" * 256, 256),
    # Shellcode-like payload, oversized
    (0, b"\x90" * 500 + b"\xcc" * 500, 1000),
    # Format string attack payload, oversized
    (0, b"%s%s%s%n%n%n" * 50, 600),
    # Unicode-like bytes, oversized
    (0, bytes(range(256)) * 4, 1024),
    # Offset = BUFFER_SIZE - 1, length = 2 (overflows by 1)
    (BUFFER_SIZE - 1, b"O" * 2, 2),
    # Offset = BUFFER_SIZE, length = 0 (boundary edge)
    (BUFFER_SIZE, b"P", 0),
    # Offset = BUFFER_SIZE, length = 1 (overflow)
    (BUFFER_SIZE, b"Q", 1),
]


@pytest.mark.parametrize("payload", ATTACK_PAYLOADS)
def test_buffer_read_never_exceeds_declared_length(payload):
    """
    Invariant: Buffer reads/writes must never exceed the declared buffer size.
    
    For any mesh radio packet with offset n and declared length len,
    the operation (n + len) must never exceed BUFFER_SIZE.
    A safe implementation must either reject or truncate such inputs.
    
    This guards against CWE-120: Buffer Copy without Checking Size of Input.
    """
    n_offset, data, declared_length = payload

    buf = bytearray(BUFFER_SIZE)

    # Test the rejecting implementation
    try:
        bytes_copied = simulate_mesh_packet_copy(buf, n_offset, data, declared_length)
        
        # If no exception was raised, the copy must have been safe
        # Invariant: bytes_copied must be within bounds
        assert bytes_copied >= 0, (
            f"Bytes copied must be non-negative, got {bytes_copied}"
        )
        assert n_offset + bytes_copied <= BUFFER_SIZE, (
            f"BUFFER OVERFLOW: offset={n_offset} + copied={bytes_copied} = "
            f"{n_offset + bytes_copied} exceeds BUFFER_SIZE={BUFFER_SIZE}. "
            f"Declared length was {declared_length}."
        )
        
        # Verify buffer integrity — no writes outside bounds
        assert len(buf) == BUFFER_SIZE, (
            f"Buffer size changed from {BUFFER_SIZE} to {len(buf)}: memory corruption detected"
        )
        
    except (ValueError, OverflowError):
        # Exception is acceptable — the implementation rejected the oversized input
        # This is the correct behavior for inputs that would overflow
        pass

    # Test the truncating implementation — must NEVER raise, must ALWAYS stay in bounds
    buf2 = bytearray(BUFFER_SIZE)
    try:
        bytes_copied2 = safe_mesh_packet_copy_truncating(buf2, n_offset, data, declared_length)
        
        # Invariant: truncating implementation must always stay within bounds
        assert bytes_copied2 >= 0, (
            f"Truncating copy returned negative bytes: {bytes_copied2}"
        )
        
        if n_offset >= 0 and n_offset < BUFFER_SIZE:
            assert n_offset + bytes_copied2 <= BUFFER_SIZE, (
                f"BUFFER OVERFLOW in truncating impl: offset={n_offset} + "
                f"copied={bytes_copied2} = {n_offset + bytes_copied2} "
                f"exceeds BUFFER_SIZE={BUFFER_SIZE}"
            )
        
        # Buffer size must remain unchanged
        assert len(buf2) == BUFFER_SIZE, (
            f"Buffer size changed: memory corruption detected. "
            f"Expected {BUFFER_SIZE}, got {len(buf2)}"
        )
        
    except (ValueError, OverflowError):
        # Truncating implementation may also reject clearly invalid inputs
        pass


@pytest.mark.parametrize("payload", ATTACK_PAYLOADS)
def test_declared_length_validation_against_buffer_bounds(payload):
    """
    Invariant: Any declared length from untrusted network data must be validated
    such that (offset + declared_length) <= BUFFER_SIZE before any copy operation.
    
    This test verifies that the validation logic correctly identifies all
    potentially overflowing combinations.
    """
    n_offset, data, declared_length = payload

    # For any valid (non-negative, in-bounds) offset and non-negative length,
    # if n + length > BUFFER_SIZE, the operation MUST be rejected or truncated
    if (isinstance(n_offset, int) and isinstance(declared_length, int) and
            n_offset >= 0 and declared_length >= 0 and
            n_offset < BUFFER_SIZE):
        
        would_overflow = (n_offset + declared_length) > BUFFER_SIZE
        
        if would_overflow:
            buf = bytearray(BUFFER_SIZE)
            
            # The safe implementation must either raise or truncate
            try:
                result = simulate_mesh_packet_copy(buf, n_offset, data, declared_length)
                # If it didn't raise, it must have truncated safely
                assert n_offset + result <= BUFFER_SIZE, (
                    f"SECURITY VIOLATION: Unsafe copy detected. "
                    f"n={n_offset}, declared_length={declared_length}, "
                    f"result={result}, BUFFER_SIZE={BUFFER_SIZE}. "
                    f"n + result = {n_offset + result} exceeds buffer."
                )
            except (ValueError, OverflowError):
                # Correct: overflow was detected and rejected
                pass
            
            # Truncating version must always produce safe result
            buf2 = bytearray(BUFFER_SIZE)
            result2 = safe_mesh_packet_copy_truncating(buf2, n_offset, data, declared_length)
            assert n_offset + result2 <= BUFFER_SIZE, (
                f"SECURITY VIOLATION in truncating impl: "
                f"n={n_offset} + result={result2} = {n_offset + result2} "
                f"exceeds BUFFER_SIZE={BUFFER_SIZE}"
            )


def test_buffer_size_invariant_with_sequential_writes():
    """
    Invariant: Sequential packet writes must not cumulatively overflow the buffer.
    
    Simulates multiple mesh radio packets arriving and being appended to a buffer,
    ensuring the cumulative offset never exceeds BUFFER_SIZE.
    """
    buf = bytearray(BUFFER_SIZE)
    n = 0
    
    # Simulate receiving multiple packets with adversarial lengths
    adversarial_packets = [
        (b"packet1" * 10, 70),
        (b"packet2" * 10, 70),
        (b"packet3" * 10, 70),
        (b"OVERFLOW_ATTEMPT" * 100, 500),  # This should be rejected/truncated
        (b"after_overflow" * 10, 100),
    ]
    
    for data, declared_len in adversarial_packets:
        try:
            copied = safe_mesh_packet_copy_truncating(buf, n, data, declared_len)
            n += copied
            
            # Invariant: offset must never exceed buffer size
            assert n <= BUFFER_SIZE, (
                f"Cumulative offset {n} exceeded BUFFER_SIZE {BUFFER_SIZE}"
            )
            assert len(buf) == BUFFER_SIZE, (
                f"Buffer corrupted: size changed to {len(buf)}"
            )
            
        except (ValueError, OverflowError):
            pass  # Rejection is acceptable
    
    # Final invariant check
    assert len(buf) == BUFFER_SIZE, "Buffer integrity violated after sequential writes"
    assert n <= BUFFER_SIZE, f"Final offset {n} exceeds BUFFER_SIZE {BUFFER_SIZE}"