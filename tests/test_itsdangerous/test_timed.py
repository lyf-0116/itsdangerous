from datetime import datetime
from datetime import timedelta
from datetime import timezone
from functools import partial
from io import BytesIO
from io import StringIO

import pytest
from freezegun import freeze_time

from itsdangerous.exc import BadTimeSignature
from itsdangerous.exc import SignatureExpired
from itsdangerous.signer import Signer
from itsdangerous.timed import TimedSerializer
from itsdangerous.timed import TimestampSigner


class FreezeMixin:
    @pytest.fixture()
    def ts(self):
        return datetime(2011, 6, 24, 0, 9, 5, tzinfo=timezone.utc)

    @pytest.fixture(autouse=True)
    def freeze(self, ts):
        with freeze_time(ts) as ft:
            yield ft


class TestTimestampSigner(FreezeMixin):
    @pytest.fixture()
    def signer_factory(self):
        return partial(TimestampSigner, secret_key="secret-key")

    @pytest.fixture()
    def signer(self, signer_factory):
        return signer_factory()

    def test_max_age(self, signer, ts, freeze):
        signed = signer.sign("value")
        freeze.tick()
        assert signer.unsign(signed, max_age=10) == b"value"
        freeze.tick(timedelta(seconds=10))

        with pytest.raises(SignatureExpired) as exc_info:
            signer.unsign(signed, max_age=10)

        assert exc_info.value.date_signed == ts

    def test_return_timestamp(self, signer, ts):
        signed = signer.sign("value")
        assert signer.unsign(signed, max_age=10, return_timestamp=True) == (
            b"value",
            ts,
        )

    def test_max_age_required(self, signer):
        signed = signer.sign("value")

        with pytest.raises(TypeError):
            signer.unsign(signed)

        with pytest.raises(TypeError):
            signer.unsign(signed, max_age=None)

        with pytest.raises(TypeError):
            signer.validate(signed)

    def test_timestamp_missing(self, signer):
        other = Signer("secret-key")
        signed = other.sign("value")

        with pytest.raises(BadTimeSignature) as exc_info:
            signer.unsign(signed, max_age=10)

        assert "missing" in str(exc_info.value)
        assert exc_info.value.date_signed is None

    def test_malformed_timestamp(self, signer):
        other = Signer("secret-key")
        signed = other.sign(b"value.____________")

        with pytest.raises(BadTimeSignature) as exc_info:
            signer.unsign(signed, max_age=10)

        assert "Malformed" in str(exc_info.value)
        assert exc_info.value.date_signed is None

    def test_malformed_future_timestamp(self, signer):
        signed = b"value.TgPVoaGhoQ.AGBfQ6G6cr07byTRt0zAdPljHOY"

        with pytest.raises(BadTimeSignature) as exc_info:
            signer.unsign(signed, max_age=10)

        assert "Malformed" in str(exc_info.value)
        assert exc_info.value.date_signed is None

    def test_future_age(self, signer):
        signed = signer.sign("value")

        with freeze_time("1971-05-31"):
            with pytest.raises(SignatureExpired) as exc_info:
                signer.unsign(signed, max_age=10)

        assert isinstance(exc_info.value.date_signed, datetime)

    def test_sig_error_date_signed(self, signer):
        signed = signer.sign("my string").replace(b"my", b"other", 1)

        with pytest.raises(BadTimeSignature) as exc_info:
            signer.unsign(signed, max_age=10)

        assert isinstance(exc_info.value.date_signed, datetime)
        assert not hasattr(exc_info.value, "payload")


class TestTimedSerializer(FreezeMixin):
    load_kwargs = {"max_age": 10}

    @pytest.fixture()
    def serializer_factory(self):
        return partial(TimedSerializer, secret_key="secret_key")

    @pytest.fixture()
    def serializer(self, serializer_factory):
        return serializer_factory()

    @pytest.fixture()
    def value(self):
        return {"id": 42}

    def test_serializer(self, serializer: TimedSerializer, value):
        assert serializer.loads(serializer.dumps(value), max_age=10) == value

    def test_max_age(self, serializer, value, ts, freeze):
        signed = serializer.dumps(value)
        freeze.tick()
        assert serializer.loads(signed, max_age=10) == value
        freeze.tick(timedelta(seconds=10))

        with pytest.raises(SignatureExpired) as exc_info:
            serializer.loads(signed, max_age=10)

        assert exc_info.value.date_signed == ts
        assert not hasattr(exc_info.value, "payload")

    def test_return_payload(self, serializer, value, ts):
        signed = serializer.dumps(value)
        assert serializer.loads(signed, max_age=10, return_timestamp=True) == (
            value,
            ts,
        )

    def test_max_age_required(self, serializer, value):
        signed = serializer.dumps(value)

        with pytest.raises(TypeError):
            serializer.loads(signed)

        with pytest.raises(TypeError):
            serializer.loads_unsafe(signed)

    def test_loads_unsafe(self, serializer, value):
        signed = serializer.dumps(value)
        assert serializer.loads_unsafe(signed, max_age=10) == (True, value)
        assert serializer.loads_unsafe(signed[:-1], max_age=10) == (False, value)

    def test_file(self, serializer, value):
        f = BytesIO() if isinstance(serializer.dumps(value), bytes) else StringIO()
        serializer.dump(value, f)
        f.seek(0)
        assert serializer.load(f, max_age=10) == value
        f.seek(0)
        assert serializer.load_unsafe(f, max_age=10) == (True, value)
