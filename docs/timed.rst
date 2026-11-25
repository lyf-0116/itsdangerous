.. module:: itsdangerous.timed

Signing With Timestamps
=======================

If you want to expire signatures you can use the
:class:`TimestampSigner` class which adds timestamp information and
signs it. Unsigning requires a maximum age, and the signature is
rejected if its timestamp is older than that age.

.. code-block:: python

    from itsdangerous import TimestampSigner
    s = TimestampSigner('secret-key')
    string = s.sign('foo')

.. code-block:: python

    s.unsign(string, max_age=5)
    Traceback (most recent call last):
      ...
    itsdangerous.exc.SignatureExpired: Signature age 15 > 5 seconds

The exception only reports metadata such as the signing time. It does
not include the unverified payload. The same requirement applies to
``TimedSerializer.loads``, ``loads_unsafe``, ``load``, and
``load_unsafe``.

.. autoclass:: TimestampSigner
    :members:

.. autoclass:: TimedSerializer
    :members:
