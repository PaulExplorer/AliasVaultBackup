from __future__ import annotations

from aliasvault_backup import srp

SALT = "0A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F"
IDENTITY = "testuser"
PASSWORD_HASH = "AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899"


def test_fixed_private_key_and_verifier() -> None:
    private_key = srp.derive_private_key(SALT, IDENTITY, PASSWORD_HASH)
    assert (
        private_key
        == "37D921B103087DDBCFEE50E240DBF5904BBC021BD07391F206CA74BE5430D79B"
    )

    verifier = srp.derive_verifier(private_key)
    assert verifier == (
        "603ABD0F6C5494976B140BBF29D988989FD88654438994959D851C83FC891FA2"
        "2C81B7CD3B1BBC5472651473183789A4DB5454D530BDEF328DCBA19C112ED266"
        "584D8750AEFDCFC0076FD40B3E16773672994C7CB56B4F6CD5FCA47927F9688"
        "483937890054D208DDBDD5117F18461B6AD7A279495583B7D99CDC1EB678E940"
        "2171F43DC7732549B5A5A3A4A2BF586686887E09D1DED55A7945C20F4DB6291"
        "5DCF7FD4D7ECED87758B3E19E25CFC668FDB92FCE15E9452DE7F78BDB9BC80D"
        "E25882769870E156B2860A169F33045298CEC7700975E3EF4AAE5B41CE6086E2"
        "593EDCF2BEA8F3B613258259197C4AE8A67055ED5546C83F6EF035BA788EC63A"
        "1AE"
    )


def test_fixed_session_key_and_proof() -> None:
    private_key = srp.derive_private_key(SALT, IDENTITY, PASSWORD_HASH)
    session = srp.derive_session(
        "89697cc13c1cea1f44c5f6b3f8f0cb7ce28246c80de10ca5d4976575dbcb0318",
        "523d0e314fccaace5ad5007357b07bb2fb2c5f566be0b812cbe4ffa65adc5bdd"
        "5cd59d9ca921b7491481d2963733513968e7bea637a733665f8e9fb7a18ba613"
        "a03740eed9ea3795489659a486cd87352054ed49f0636bb2605b8d836a459151"
        "cb670d35e8377202d9e1569bf88d0c86bd83d303d8775a65867b68fc7f9a9d5d"
        "59c76c413cb1b4d33f1d5eb784d1d18a5705800729a5d566548297c3b84ec107"
        "7c4546ab3c9b159a6d6c7265cdc784f36f731fa371e14bc506a544713591579d"
        "0a6952c2539746963434f0e97a024c0e93701008e4c54b620a9259d071b88c0a"
        "4cf102eaa22732ecfcd1fd23a81ee180074db1b5cee1b3e9172f76153f8d46bc",
        SALT,
        IDENTITY,
        private_key,
    )
    assert (
        session.key
        == "AD713F5D8F520B7B9413CDD9EF6D9B5FE37F23A9B62C5E2B90D2291F8C3A9E6F"
    )
    assert (
        session.proof
        == "698D0DA7137A0FC4A55B49525C1312ADCD07788E8CD5FFF5BD195B3C17B6B3DF"
    )


def test_server_proof_verification() -> None:
    private_key = srp.derive_private_key(SALT, IDENTITY, PASSWORD_HASH)
    session = srp.derive_session(
        "89697cc13c1cea1f44c5f6b3f8f0cb7ce28246c80de10ca5d4976575dbcb0318",
        "523d0e314fccaace5ad5007357b07bb2fb2c5f566be0b812cbe4ffa65adc5bdd"
        "5cd59d9ca921b7491481d2963733513968e7bea637a733665f8e9fb7a18ba613"
        "a03740eed9ea3795489659a486cd87352054ed49f0636bb2605b8d836a459151"
        "cb670d35e8377202d9e1569bf88d0c86bd83d303d8775a65867b68fc7f9a9d5d"
        "59c76c413cb1b4d33f1d5eb784d1d18a5705800729a5d566548297c3b84ec107"
        "7c4546ab3c9b159a6d6c7265cdc784f36f731fa371e14bc506a544713591579d"
        "0a6952c2539746963434f0e97a024c0e93701008e4c54b620a9259d071b88c0a"
        "4cf102eaa22732ecfcd1fd23a81ee180074db1b5cee1b3e9172f76153f8d46bc",
        SALT,
        IDENTITY,
        private_key,
    )
    import hashlib

    expected_m2 = (
        hashlib.sha256(
            bytes.fromhex(session.client_public)
            + bytes.fromhex(session.proof)
            + bytes.fromhex(session.key)
        )
        .hexdigest()
        .upper()
    )
    assert srp.verify_server_proof(
        session.client_public, session.proof, session.key, expected_m2
    )
    assert not srp.verify_server_proof(
        session.client_public, session.proof, session.key, "00" * 32
    )
