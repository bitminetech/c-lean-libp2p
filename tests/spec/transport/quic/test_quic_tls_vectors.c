#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "peer_id/peer_id.h"
#include "quic_test_support.h"
#include "transport/quic/quic_identity.h"

static void quic_tls_vector_test_valid_secp256k1_certificate(void)
{
    static const char cert_hex[] =
        "308201ba3082015fa0030201020204499602d2300a06082a8648ce3d040302302031123010060355"
        "040a13096c69627032702e696f310a300806035504051301313020170d3735303130313133303030"
        "305a180f34303936303130313133303030305a302031123010060355040a13096c69627032702e69"
        "6f310a300806035504051301313059301306072a8648ce3d020106082a8648ce3d03010703420004"
        "0c901d423c831ca85e27c73c263ba132721bb9d7a84c4f0380b2a6756fd601331c8870234dec"
        "878504c174144fa4b14b66a651691606d8173e55bd37e381569ea38184308181307f060a2b0601"
        "040183a25a01010471306f0425080212210206dc6968726765b820f050263ececf7f71e4955892"
        "776c0970542efd689d2382044630440220145e15a991961f0d08cd15425bb95ec93f6ffa03c5"
        "a385eedc34ecf464c7a8ab022026b3109b8a3f40ef833169777eb2aa337cfb6282f188de0666"
        "d1bcec2a4690dd300a06082a8648ce3d0403020349003046022100e1a217eeef9ec9204b3f"
        "774a08b70849646b6a1e6b8b27f93dc00ed58545d9fe022100b00dafa549d0f03547878338"
        "c7b15e7502888f6d45db387e5ae6b5d46899cef0";
    static const char peer_id_text[] = "16Uiu2HAkutTMoTzDw1tCvSRtu6YoixJwS46S1ZFxW8hSx9fWHiPs";
    uint8_t cert[1024];
    uint8_t peer_id[LIBP2P_PEER_ID_MAX_BYTES];
    size_t cert_len = 0U;
    size_t peer_id_len = 0U;
    libp2p_quic_const_buffer_t chain[1];
    libp2p_quic_peer_identity_t peer;
    libp2p_quic_certificate_report_t report;

    quic_test_parse_hex(cert_hex, cert, sizeof(cert), &cert_len);
    assert(
        libp2p_peer_id_from_string(
            peer_id_text,
            strlen(peer_id_text),
            peer_id,
            sizeof(peer_id),
            &peer_id_len) == LIBP2P_PEER_ID_OK);

    chain[0].data = cert;
    chain[0].len = cert_len;
    assert(
        libp2p_quic_identity_verify_peer_certificate_chain(
            chain,
            1U,
            peer_id,
            peer_id_len,
            UINT64_C(1750000000),
            &peer,
            &report) == LIBP2P_QUIC_OK);
    assert(report.self_signature_valid == 1U);
    assert(report.libp2p_extension_present == 1U);
    assert(report.unknown_critical_extension_present == 0U);
    assert(peer.peer_id_len == peer_id_len);
    assert(memcmp(peer.peer_id, peer_id, peer_id_len) == 0);
}

static void quic_tls_vector_test_rejects_mismatched_expected_peer_id(void)
{
    static const char cert_hex[] =
        "308201ba3082015fa0030201020204499602d2300a06082a8648ce3d040302302031123010060355"
        "040a13096c69627032702e696f310a300806035504051301313020170d3735303130313133303030"
        "305a180f34303936303130313133303030305a302031123010060355040a13096c69627032702e69"
        "6f310a300806035504051301313059301306072a8648ce3d020106082a8648ce3d03010703420004"
        "0c901d423c831ca85e27c73c263ba132721bb9d7a84c4f0380b2a6756fd601331c8870234dec"
        "878504c174144fa4b14b66a651691606d8173e55bd37e381569ea38184308181307f060a2b0601"
        "040183a25a01010471306f0425080212210206dc6968726765b820f050263ececf7f71e4955892"
        "776c0970542efd689d2382044630440220145e15a991961f0d08cd15425bb95ec93f6ffa03c5"
        "a385eedc34ecf464c7a8ab022026b3109b8a3f40ef833169777eb2aa337cfb6282f188de0666"
        "d1bcec2a4690dd300a06082a8648ce3d0403020349003046022100e1a217eeef9ec9204b3f"
        "774a08b70849646b6a1e6b8b27f93dc00ed58545d9fe022100b00dafa549d0f03547878338"
        "c7b15e7502888f6d45db387e5ae6b5d46899cef0";
    uint8_t cert[1024];
    uint8_t wrong_peer_id[LIBP2P_PEER_ID_MAX_BYTES];
    size_t cert_len = 0U;
    size_t wrong_peer_id_len = 0U;

    quic_test_parse_hex(cert_hex, cert, sizeof(cert), &cert_len);
    quic_test_parse_hex(
        "12209cbc07c3f991725836a3aa2a581ca2029198aa420b9d99bc0e131d9f3e2cbe47",
        wrong_peer_id,
        sizeof(wrong_peer_id),
        &wrong_peer_id_len);

    assert(
        libp2p_quic_identity_verify_peer_certificate(
            cert,
            cert_len,
            wrong_peer_id,
            wrong_peer_id_len,
            UINT64_C(1750000000),
            NULL) == LIBP2P_QUIC_ERR_PEER_ID_MISMATCH);
}

int main(void)
{
    quic_tls_vector_test_valid_secp256k1_certificate();
    quic_tls_vector_test_rejects_mismatched_expected_peer_id();
    return 0;
}
