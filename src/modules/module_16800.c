/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "modules.h"
#include "bitops.h"
#include "convert.h"
#include "shared.h"
#include "memory.h"

static const u32   ATTACK_EXEC    = ATTACK_EXEC_OUTSIDE_KERNEL;
static const u32   DGST_POS0      = 0;
static const u32   DGST_POS1      = 1;
static const u32   DGST_POS2      = 2;
static const u32   DGST_POS3      = 3;
static const u32   DGST_SIZE      = DGST_SIZE_4_4;
static const u32   HASH_CATEGORY  = HASH_CATEGORY_NETWORK_PROTOCOL;
static const char *HASH_NAME      = "WPA-PMKID-PBKDF2";
static const u32   HASH_TYPE      = HASH_TYPE_GENERIC;
static const u64   KERN_TYPE      = 16800;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE
                                  | OPTI_TYPE_SLOW_HASH_SIMD_LOOP;
static const u64   OPTS_TYPE      = OPTS_TYPE_STATE_BUFFER_LE
                                  | OPTS_TYPE_PT_GENERATE_LE
                                  | OPTS_TYPE_AUX1
                                  | OPTS_TYPE_DEEP_COMP_KERNEL;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat!";
static const char *ST_HASH        = "2582a8281bf9d4308d6f5731d0e61c61*4604ba734d4e*89acf0e761f4*ed487162465a774bfba60eb603a39f3a";

u32         module_attack_exec    (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return ATTACK_EXEC;     }
u32         module_dgst_pos0      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return DGST_POS0;       }
u32         module_dgst_pos1      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return DGST_POS1;       }
u32         module_dgst_pos2      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return DGST_POS2;       }
u32         module_dgst_pos3      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return DGST_POS3;       }
u32         module_dgst_size      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return DGST_SIZE;       }
u32         module_hash_category  (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return HASH_CATEGORY;   }
const char *module_hash_name      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return HASH_NAME;       }
u32         module_hash_type      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return HASH_TYPE;       }
u64         module_kern_type      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return KERN_TYPE;       }
u32         module_opti_type      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return OPTI_TYPE;       }
u64         module_opts_type      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return OPTS_TYPE;       }
u32         module_salt_type      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return SALT_TYPE;       }
const char *module_st_hash        (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return ST_HASH;         }
const char *module_st_pass        (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return ST_PASS;         }

static const u32 ROUNDS_WPA_PBKDF2 = 4096;

typedef struct wpa_pmkid
{
  u32  pmkid[4];
  u32  pmkid_data[16];
  u8   orig_mac_ap[6];
  u8   orig_mac_sta[6];
  u8   essid_len;
  u32  essid_buf[16];

} wpa_pmkid_t;

typedef struct wpa_pbkdf2_tmp
{
  u32 ipad[5];
  u32 opad[5];

  u32 dgst[10];
  u32 out[10];

} wpa_pbkdf2_tmp_t;

const char *module_benchmark_mask (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const char *mask = "?a?a?a?a?a?a?a?a";

  return mask;
}

u64 module_tmp_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 tmp_size = (const u64) sizeof (wpa_pbkdf2_tmp_t);

  return tmp_size;
}

u64 module_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 esalt_size = (const u64) sizeof (wpa_pmkid_t);

  return esalt_size;
}

u32 module_pw_min (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u32 pw_min = 8;

  return pw_min;
}

u32 module_pw_max (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u32 pw_max = 63;

  return pw_max;
}

u32 module_deep_comp_kernel (MAYBE_UNUSED const hashes_t *hashes, MAYBE_UNUSED const u32 salt_pos, MAYBE_UNUSED const u32 digest_pos)
{
  return KERN_RUN_AUX1;
}

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  wpa_pmkid_t *wpa_pmkid = (wpa_pmkid_t *) esalt_buf;

  token_t token;

  token.token_cnt  = 4;

  token.sep[0]     = '*';
  token.len_min[0] = 32;
  token.len_max[0] = 32;
  token.attr[0]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.sep[1]     = '*';
  token.len_min[1] = 12;
  token.len_max[1] = 12;
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.sep[2]     = '*';
  token.len_min[2] = 12;
  token.len_max[2] = 12;
  token.attr[2]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.sep[3]     = '*';
  token.len_min[3] = 0;
  token.len_max[3] = 64;
  token.attr[3]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  // pmkid

  const u8 *pmkid_buf = token.buf[0];

  wpa_pmkid->pmkid[0] = hex_to_u32 (pmkid_buf +  0);
  wpa_pmkid->pmkid[1] = hex_to_u32 (pmkid_buf +  8);
  wpa_pmkid->pmkid[2] = hex_to_u32 (pmkid_buf + 16);
  wpa_pmkid->pmkid[3] = hex_to_u32 (pmkid_buf + 24);

  // mac_ap

  const u8 *macap_buf = token.buf[1];

  wpa_pmkid->orig_mac_ap[0] = hex_to_u8 (macap_buf +  0);
  wpa_pmkid->orig_mac_ap[1] = hex_to_u8 (macap_buf +  2);
  wpa_pmkid->orig_mac_ap[2] = hex_to_u8 (macap_buf +  4);
  wpa_pmkid->orig_mac_ap[3] = hex_to_u8 (macap_buf +  6);
  wpa_pmkid->orig_mac_ap[4] = hex_to_u8 (macap_buf +  8);
  wpa_pmkid->orig_mac_ap[5] = hex_to_u8 (macap_buf + 10);

  // mac_sta

  const u8 *macsta_buf = token.buf[2];

  wpa_pmkid->orig_mac_sta[0] = hex_to_u8 (macsta_buf +  0);
  wpa_pmkid->orig_mac_sta[1] = hex_to_u8 (macsta_buf +  2);
  wpa_pmkid->orig_mac_sta[2] = hex_to_u8 (macsta_buf +  4);
  wpa_pmkid->orig_mac_sta[3] = hex_to_u8 (macsta_buf +  6);
  wpa_pmkid->orig_mac_sta[4] = hex_to_u8 (macsta_buf +  8);
  wpa_pmkid->orig_mac_sta[5] = hex_to_u8 (macsta_buf + 10);

  // essid

  const u8 *essid_buf = token.buf[3];
  const int essid_len = token.len[3];

  u8 *essid_ptr = (u8 *) wpa_pmkid->essid_buf;

  for (int i = 0, j = 0; i < essid_len; i += 2, j += 1)
  {
    essid_ptr[j] = hex_to_u8 (essid_buf + i);
  }

  wpa_pmkid->essid_len = essid_len / 2;

  // pmkid_data

  wpa_pmkid->pmkid_data[0] = 0x204b4d50; // "PMK "
  wpa_pmkid->pmkid_data[1] = 0x656d614e; // "Name"
  wpa_pmkid->pmkid_data[2] = (wpa_pmkid->orig_mac_ap[0]  <<  0)
                           | (wpa_pmkid->orig_mac_ap[1]  <<  8)
                           | (wpa_pmkid->orig_mac_ap[2]  << 16)
                           | (wpa_pmkid->orig_mac_ap[3]  << 24);
  wpa_pmkid->pmkid_data[3] = (wpa_pmkid->orig_mac_ap[4]  <<  0)
                           | (wpa_pmkid->orig_mac_ap[5]  <<  8)
                           | (wpa_pmkid->orig_mac_sta[0] << 16)
                           | (wpa_pmkid->orig_mac_sta[1] << 24);
  wpa_pmkid->pmkid_data[4] = (wpa_pmkid->orig_mac_sta[2] <<  0)
                           | (wpa_pmkid->orig_mac_sta[3] <<  8)
                           | (wpa_pmkid->orig_mac_sta[4] << 16)
                           | (wpa_pmkid->orig_mac_sta[5] << 24);

  // salt

  memcpy (salt->salt_buf, wpa_pmkid->essid_buf, wpa_pmkid->essid_len);

  salt->salt_len = wpa_pmkid->essid_len;

  salt->salt_iter = ROUNDS_WPA_PBKDF2 - 1;

  // hash

  digest[0] = wpa_pmkid->pmkid[0];
  digest[1] = wpa_pmkid->pmkid[1];
  digest[2] = wpa_pmkid->pmkid[2];
  digest[3] = wpa_pmkid->pmkid[3];

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);

  return (PARSER_OK);
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const wpa_pmkid_t *wpa_pmkid = (const wpa_pmkid_t *) esalt_buf;

  char tmp_buf[128];

  exec_hexify ((const u8*) wpa_pmkid->essid_buf, wpa_pmkid->essid_len, (u8 *) tmp_buf);

  const int tmp_len = wpa_pmkid->essid_len * 2;

  tmp_buf[tmp_len] = 0;

  const int line_len = snprintf (line_buf, line_size, "%08x%08x%08x%08x*%02x%02x%02x%02x%02x%02x*%02x%02x%02x%02x%02x%02x*%s",
    byte_swap_32 (wpa_pmkid->pmkid[0]),
    byte_swap_32 (wpa_pmkid->pmkid[1]),
    byte_swap_32 (wpa_pmkid->pmkid[2]),
    byte_swap_32 (wpa_pmkid->pmkid[3]),
    wpa_pmkid->orig_mac_ap[0],
    wpa_pmkid->orig_mac_ap[1],
    wpa_pmkid->orig_mac_ap[2],
    wpa_pmkid->orig_mac_ap[3],
    wpa_pmkid->orig_mac_ap[4],
    wpa_pmkid->orig_mac_ap[5],
    wpa_pmkid->orig_mac_sta[0],
    wpa_pmkid->orig_mac_sta[1],
    wpa_pmkid->orig_mac_sta[2],
    wpa_pmkid->orig_mac_sta[3],
    wpa_pmkid->orig_mac_sta[4],
    wpa_pmkid->orig_mac_sta[5],
    tmp_buf);

  return line_len;
}

void module_init (module_ctx_t *module_ctx)
{
  module_ctx->module_context_size             = MODULE_CONTEXT_SIZE_CURRENT;
  module_ctx->module_interface_version        = MODULE_INTERFACE_VERSION_CURRENT;

  module_ctx->module_attack_exec              = module_attack_exec;
  module_ctx->module_benchmark_esalt          = MODULE_DEFAULT;
  module_ctx->module_benchmark_hook_salt      = MODULE_DEFAULT;
  module_ctx->module_benchmark_mask           = module_benchmark_mask;
  module_ctx->module_benchmark_salt           = MODULE_DEFAULT;
  module_ctx->module_build_plain_postprocess  = MODULE_DEFAULT;
  module_ctx->module_deep_comp_kernel         = module_deep_comp_kernel;
  module_ctx->module_dgst_pos0                = module_dgst_pos0;
  module_ctx->module_dgst_pos1                = module_dgst_pos1;
  module_ctx->module_dgst_pos2                = module_dgst_pos2;
  module_ctx->module_dgst_pos3                = module_dgst_pos3;
  module_ctx->module_dgst_size                = module_dgst_size;
  module_ctx->module_dictstat_disable         = MODULE_DEFAULT;
  module_ctx->module_esalt_size               = module_esalt_size;
  module_ctx->module_extra_buffer_size        = MODULE_DEFAULT;
  module_ctx->module_forced_outfile_format    = MODULE_DEFAULT;
  module_ctx->module_hash_binary_count        = MODULE_DEFAULT;
  module_ctx->module_hash_binary_parse        = MODULE_DEFAULT;
  module_ctx->module_hash_binary_save         = MODULE_DEFAULT;
  module_ctx->module_hash_binary_verify       = MODULE_DEFAULT;
  module_ctx->module_hash_decode_outfile      = MODULE_DEFAULT;
  module_ctx->module_hash_decode_zero_hash    = MODULE_DEFAULT;
  module_ctx->module_hash_decode              = module_hash_decode;
  module_ctx->module_hash_encode_status       = MODULE_DEFAULT;
  module_ctx->module_hash_encode              = module_hash_encode;
  module_ctx->module_hash_init_selftest       = MODULE_DEFAULT;
  module_ctx->module_hash_mode                = MODULE_DEFAULT;
  module_ctx->module_hash_category            = module_hash_category;
  module_ctx->module_hash_name                = module_hash_name;
  module_ctx->module_hash_type                = module_hash_type;
  module_ctx->module_hlfmt_disable            = MODULE_DEFAULT;
  module_ctx->module_hook12                   = MODULE_DEFAULT;
  module_ctx->module_hook23                   = MODULE_DEFAULT;
  module_ctx->module_hook_salt_size           = MODULE_DEFAULT;
  module_ctx->module_hook_size                = MODULE_DEFAULT;
  module_ctx->module_jit_build_options        = MODULE_DEFAULT;
  module_ctx->module_kernel_accel_max         = MODULE_DEFAULT;
  module_ctx->module_kernel_accel_min         = MODULE_DEFAULT;
  module_ctx->module_kernel_loops_max         = MODULE_DEFAULT;
  module_ctx->module_kernel_loops_min         = MODULE_DEFAULT;
  module_ctx->module_kernel_threads_max       = MODULE_DEFAULT;
  module_ctx->module_kernel_threads_min       = MODULE_DEFAULT;
  module_ctx->module_kern_type                = module_kern_type;
  module_ctx->module_opti_type                = module_opti_type;
  module_ctx->module_opts_type                = module_opts_type;
  module_ctx->module_outfile_check_disable    = MODULE_DEFAULT;
  module_ctx->module_outfile_check_nocomp     = MODULE_DEFAULT;
  module_ctx->module_potfile_disable          = MODULE_DEFAULT;
  module_ctx->module_potfile_keep_all_hashes  = MODULE_DEFAULT;
  module_ctx->module_pwdump_column            = MODULE_DEFAULT;
  module_ctx->module_pw_max                   = module_pw_max;
  module_ctx->module_pw_min                   = module_pw_min;
  module_ctx->module_salt_max                 = MODULE_DEFAULT;
  module_ctx->module_salt_min                 = MODULE_DEFAULT;
  module_ctx->module_salt_type                = module_salt_type;
  module_ctx->module_separator                = MODULE_DEFAULT;
  module_ctx->module_st_hash                  = module_st_hash;
  module_ctx->module_st_pass                  = module_st_pass;
  module_ctx->module_tmp_size                 = module_tmp_size;
  module_ctx->module_unstable_warning         = MODULE_DEFAULT;
  module_ctx->module_warmup_disable           = MODULE_DEFAULT;
}