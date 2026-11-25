.. module:: itsdangerous.serializer

Serialization Interface
=======================

The :doc:`/signer` only signs bytes. To sign other types, the
:class:`Serializer` class provides a ``dumps``/``loads`` interface
similar to Python's :mod:`json` module, which serializes the object to a
string then signs that.

Use :meth:`~Serializer.dumps` to serialize and sign the data:

.. code-block:: python

    from itsdangerous.serializer import Serializer
    s = Serializer("secret-key")
    s.dumps([1, 2, 3, 4])
    b'[1, 2, 3, 4].r7R9RhGgDPvvWl3iNzLuIIfELmo'

Use :meth:`~Serializer.loads` to verify the signature and deserialize
the data.

.. code-block:: python

    s.loads('[1, 2, 3, 4].r7R9RhGgDPvvWl3iNzLuIIfELmo')
    [1, 2, 3, 4]

By default, data is serialized to JSON with the built-in :mod:`json`
module. This internal serializer can be changed by subclassing.

To record and validate the age of the signature, see :doc:`/timed`.
To serialize to a format that is safe to use in URLs, see
:doc:`/url_safe`.


Responding to Failure
---------------------

Exceptions only contain metadata about the failure, such as the signing
time on an expired signature. They do not contain the unverified
payload, since that data may have been controlled by an attacker.

.. code-block:: python

    from itsdangerous.serializer import Serializer
    from itsdangerous.exc import BadSignature

    s = URLSafeSerializer("secret-key")

    try:
        payload = s.loads(data)
        # This payload is decoded and safe
    except BadSignature:
        # The input is untrusted. Do not decode or log its payload.
        payload = None

If you explicitly need to debug an invalid value, you can use
:meth:`~Serializer.loads_unsafe`:

.. code-block:: python

    sig_okay, payload = s.loads_unsafe(data)

The first item in the returned tuple is a boolean that indicates if the
signature was correct. The payload is returned even when the signature
is invalid, so treat it as unsafe in that case.


Fallback Signers
----------------

You may want to upgrade the signing parameters without invalidating
existing signatures immediately. For example, you may decide that you
want to use a different digest method. New signatures should use the new
method, but old signatures should still validate.

A list of ``fallback_signers`` can be given that will be tried if
unsigning with the current signer fails. Each item in the list can be:

-   A dict of ``signer_kwargs`` to instantiate the ``signer`` class
    passed to the serializer.
-   A :class:`~itsdangerous.signer.Signer` class to instantiated with
    the ``secret_key``, ``salt``, and ``signer_kwargs`` passed to the
    serializer.
-   A tuple of ``(signer_class, signer_kwargs)`` to instantiate the
    given class with the given args.

For example, this is a serializer that signs using SHA-512, but will
unsign using either SHA-512 or SHA-1:

.. code-block:: python

    s = Serializer(
        signer_kwargs={"digest_method": hashlib.sha512},
        fallback_signers=[{"digest_method": hashlib.sha1}]
    )



API
---

.. autoclass:: Serializer
    :members:
