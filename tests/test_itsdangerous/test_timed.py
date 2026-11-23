from datetime import datetime
from datetime import timedelta
from datetime import timezone
from functools import partial

import pytest
from freezegun import freeze_time

from itsdangerous.exc import BadTimeSignature
from itsdangerous.exc import SignatureExpired
from itsdangerous.signer import Signer
from itsdangerous.timed import TimedSerializer
from itsdangerous.timed import TimestampSigner
from test_itsdangerous.test_serializer import TestSerializer
from test_itsdangerous.test_signer import TestSigner


class FreezeMixin:
    @pytest.fixture()
    def ts(self):
        return datetime(2011, 6, 24, 0, 9, 5, tzinfo=timezone.utc)

    @pytest.fixture(autouse=True)
    def freeze(self, ts):
        with freeze_time(ts) as ft:
            yield ft


class TestTimestampSigner(FreezeMixin, TestSigner):
    @pytest.fixture()
    def signer_factory(self):
        return partial(TimestampSigner, secret_key="secret-key")

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
        assert signer.unsign(signed, return_timestamp=True) == (b"value", ts)

    def test_timestamp_missing(self, signer):
        other = Signer("secret-key")
        signed = other.sign("value")

        with pytest.raises(BadTimeSignature) as exc_info:
            signer.unsign(signed)

        assert "missing" in str(exc_info.value)
        assert exc_info.value.date_signed is None

    def test_malformed_timestamp(self, signer):
        other = Signer("secret-key")
        signed = other.sign(b"value.____________")

        with pytest.raises(BadTimeSignature) as exc_info:
            signer.unsign(signed)

        assert "Malformed" in str(exc_info.value)
        assert exc_info.value.date_signed is None

    def test_malformed_future_timestamp(self, signer):
        signed = b"value.TgPVoaGhoQ.AGBfQ6G6cr07byTRt0zAdPljHOY"

        with pytest.raises(BadTimeSignature) as exc_info:
            signer.unsign(signed)

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
            signer.unsign(signed)

        assert isinstance(exc_info.value.date_signed, datetime)


class TestTimedSerializer(FreezeMixin, TestSerializer):
    @pytest.fixture()
    def serializer_factory(self):
        return partial(TimedSerializer, secret_key="secret_key")

    def test_max_age(self, serializer, value, ts, freeze):
        signed = serializer.dumps(value)
        freeze.tick()
        assert serializer.loads(signed, max_age=10) == value
        freeze.tick(timedelta(seconds=10))

        with pytest.raises(SignatureExpired) as exc_info:
            serializer.loads(signed, max_age=10)

        assert exc_info.value.date_signed == ts
        assert serializer.load_payload(exc_info.value.payload) == value

    def test_return_payload(self, serializer, value, ts):
        signed = serializer.dumps(value)
        assert serializer.loads(signed, return_timestamp=True) == (value, ts)

    def test_positional_salt(self, serializer, value):
        # The base Serializer.loads takes salt as its second positional
        # argument. A str or bytes value must be dispatched as salt.
        signed = serializer.dumps(value, salt="other")

        with pytest.raises(BadTimeSignature):
            serializer.loads(signed)

        assert serializer.loads(signed, "other") == value

    def test_positional_max_age(self, serializer, value, ts, freeze):
        # Existing callers pass max_age as the second positional argument.
        signed = serializer.dumps(value)
        freeze.tick()
        assert serializer.loads(signed, 10) == value
        freeze.tick(timedelta(seconds=10))

        with pytest.raises(SignatureExpired):
            serializer.loads(signed, 10)

    def test_positional_salt_and_keyword_max_age(self, serializer, value, freeze):
        signed = serializer.dumps(value, salt="other")
        freeze.tick()
        assert serializer.loads(signed, "other", max_age=10) == value
        freeze.tick(timedelta(seconds=10))

        with pytest.raises(SignatureExpired):
            serializer.loads(signed, "other", max_age=10)

    def test_duplicate_salt(self, serializer, value):
        signed = serializer.dumps(value, salt="other")

        with pytest.raises(TypeError):
            serializer.loads(signed, "other", salt="other")

    def test_loads_unsafe_positional_salt(self, serializer, value):
        signed = serializer.dumps(value, salt="other")
        assert serializer.loads_unsafe(signed, "other") == (True, value)
