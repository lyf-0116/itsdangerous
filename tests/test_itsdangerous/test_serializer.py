import hashlib
import pickle
from functools import partial
from io import BytesIO
from io import StringIO
from typing import Any
from typing import cast
from typing import IO
from typing import overload

import pytest

from itsdangerous.exc import BadPayload
from itsdangerous.exc import BadSignature
from itsdangerous.serializer import Serializer
from itsdangerous.signer import _lazy_sha1
from itsdangerous.signer import Signer


@overload
def coerce_str(ref: str, s: str) -> str: ...


@overload
def coerce_str(ref: bytes, s: str) -> bytes: ...


def coerce_str(ref: str | bytes, s: str) -> str | bytes:
    if isinstance(ref, bytes):
        return s.encode("utf8")

    return s


class TestSerializer:
    load_kwargs: dict[str, Any] = {}

    @pytest.fixture(params=(Serializer, partial(Serializer, serializer=pickle)))
    def serializer_factory(self, request):
        return partial(request.param, secret_key="secret_key")

    @pytest.fixture()
    def serializer(self, serializer_factory):
        return serializer_factory()

    @pytest.fixture()
    def value(self):
        return {"id": 42}

    def load(self, serializer: Serializer, s: str | bytes, **kwargs: Any) -> Any:
        return serializer.loads(s, **self.load_kwargs, **kwargs)

    def load_unsafe(
        self, serializer: Serializer, s: str | bytes, **kwargs: Any
    ) -> tuple[bool, Any]:
        return serializer.loads_unsafe(s, **self.load_kwargs, **kwargs)

    @pytest.mark.parametrize(
        "value", (None, True, "str", "text", [1, 2, 3], {"id": 42})
    )
    def test_serializer(self, serializer: Serializer, value: Any):
        assert self.load(serializer, serializer.dumps(value)) == value

    @pytest.mark.parametrize(
        "transform",
        (
            lambda s: s.upper(),
            lambda s: s + coerce_str(s, "a"),
            lambda s: coerce_str(s, "a") + s[1:],
            lambda s: s.replace(coerce_str(s, "."), coerce_str(s, "")),
        ),
    )
    def test_changed_value(self, serializer: Serializer, value: Any, transform):
        signed = serializer.dumps(value)
        assert self.load(serializer, signed) == value
        changed = transform(signed)

        with pytest.raises(BadSignature):
            self.load(serializer, changed)

    def test_bad_signature_exception(self, serializer: Serializer, value: Any):
        bad_signed = serializer.dumps(value)[:-1]

        with pytest.raises(BadSignature) as exc_info:
            self.load(serializer, bad_signed)

        assert not hasattr(exc_info.value, "payload")

    def test_bad_payload_exception(self, serializer: Serializer, value: Any):
        original = serializer.dumps(value)
        payload = original.rsplit(coerce_str(original, "."), 1)[0]  # type: ignore
        bad = serializer.make_signer().sign(payload[:-1])

        with pytest.raises(BadPayload) as exc_info:
            self.load(serializer, bad)

        assert exc_info.value.original_error is not None

    def test_loads_unsafe(self, serializer: Serializer, value: Any):
        signed = serializer.dumps(value)
        assert self.load_unsafe(serializer, signed) == (True, value)

        bad_signed = signed[:-1]
        assert self.load_unsafe(serializer, bad_signed) == (False, value)

        payload = signed.rsplit(coerce_str(signed, "."), 1)[0]  # type: ignore
        bad_payload = serializer.make_signer().sign(payload[:-1])[:-1]
        assert self.load_unsafe(serializer, bad_payload) == (False, None)

        class BadUnsign(serializer.signer):  # type: ignore
            def unsign(self, signed_value, *args, **kwargs):
                raise BadSignature("bad signature")

        serializer.signer = BadUnsign
        assert self.load_unsafe(serializer, bad_signed) == (False, value)

    def test_file(self, serializer: Serializer, value: Any):
        f = cast(
            IO, BytesIO() if isinstance(serializer.dumps(value), bytes) else StringIO()
        )
        serializer.dump(value, f)
        f.seek(0)
        assert serializer.load(f, **self.load_kwargs) == value
        f.seek(0)
        assert serializer.load_unsafe(f, **self.load_kwargs) == (True, value)

    def test_alt_salt(self, serializer: Serializer, value: Any):
        signed = serializer.dumps(value, salt="other")

        with pytest.raises(BadSignature):
            self.load(serializer, signed)

        assert self.load(serializer, signed, salt="other") == value

    def test_signer_cls(self, serializer_factory, serializer: Serializer, value: Any):
        class Other(serializer.signer):  # type: ignore
            default_key_derivation = "hmac"

        other = serializer_factory(signer=Other)
        assert self.load(other, other.dumps(value)) == value
        assert other.dumps(value) != serializer.dumps(value)

    def test_signer_kwargs(
        self, serializer_factory, serializer: Serializer, value: Any
    ):
        other = serializer_factory(signer_kwargs={"key_derivation": "hmac"})
        assert self.load(other, other.dumps(value)) == value
        assert other.dumps("value") != serializer.dumps("value")

    def test_serializer_kwargs(self, serializer_factory):
        serializer = serializer_factory(serializer_kwargs={"skipkeys": True})

        try:
            serializer.serializer.dumps(None, skipkeys=True)
        except TypeError:
            return

        assert self.load(serializer, serializer.dumps({(): 1})) == {}

    def test_fallback_signers(self, serializer_factory, value: Any):
        serializer = serializer_factory(signer_kwargs={"digest_method": hashlib.sha256})
        signed = serializer.dumps(value)

        fallback_serializer = serializer_factory(
            signer_kwargs={"digest_method": hashlib.sha1},
            fallback_signers=[{"digest_method": hashlib.sha256}],
        )

        assert self.load(fallback_serializer, signed) == value

    def test_iter_unsigners(self, serializer: Serializer, serializer_factory):
        class Signer256(serializer.signer):  # type: ignore
            default_digest_method = hashlib.sha256

        serializer = serializer_factory(
            secret_key="secret_key",
            fallback_signers=[
                {"digest_method": hashlib.sha256},
                (Signer, {"digest_method": hashlib.sha256}),
                Signer256,
            ],
        )

        unsigners = serializer.iter_unsigners()
        assert next(unsigners).digest_method == _lazy_sha1

        for signer in unsigners:
            assert signer.digest_method == hashlib.sha256


def test_digests():
    factory = partial(Serializer, secret_key="dev key", salt="dev salt")
    default_value = factory(signer_kwargs={}).dumps([42])
    sha1_value = factory(signer_kwargs={"digest_method": hashlib.sha1}).dumps([42])
    sha512_value = factory(signer_kwargs={"digest_method": hashlib.sha512}).dumps([42])
    assert default_value == sha1_value
    assert sha1_value == "[42].-9cNi0CxsSB3hZPNCe9a2eEs1ZM"
    assert sha512_value == (
        "[42].MKCz_0nXQqv7wKpfHZcRtJRmpT2T5uvs9YQsJEhJimqxc"
        "9bCLxG31QzS5uC8OVBI1i6jyOLAFNoKaF5ckO9L5Q"
    )
