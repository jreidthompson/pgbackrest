/***********************************************************************************************************************************
Command and Option Configuration

Automatically generated by 'build-code config' -- do not modify directly.
***********************************************************************************************************************************/
#ifndef CONFIG_CONFIG_AUTO_H
#define CONFIG_CONFIG_AUTO_H

/***********************************************************************************************************************************
Command constants
***********************************************************************************************************************************/
#define CFGCMD_ANNOTATE                                             "annotate"
#define CFGCMD_ARCHIVE_GET                                          "archive-get"
#define CFGCMD_ARCHIVE_PUSH                                         "archive-push"
#define CFGCMD_BACKUP                                               "backup"
#define CFGCMD_CHECK                                                "check"
#define CFGCMD_EXPIRE                                               "expire"
#define CFGCMD_HELP                                                 "help"
#define CFGCMD_INFO                                                 "info"
#define CFGCMD_MANIFEST                                             "manifest"
#define CFGCMD_REPO_CREATE                                          "repo-create"
#define CFGCMD_REPO_GET                                             "repo-get"
#define CFGCMD_REPO_LS                                              "repo-ls"
#define CFGCMD_REPO_PUT                                             "repo-put"
#define CFGCMD_REPO_RM                                              "repo-rm"
#define CFGCMD_RESTORE                                              "restore"
#define CFGCMD_SERVER                                               "server"
#define CFGCMD_SERVER_PING                                          "server-ping"
#define CFGCMD_STANZA_CREATE                                        "stanza-create"
#define CFGCMD_STANZA_DELETE                                        "stanza-delete"
#define CFGCMD_STANZA_UPGRADE                                       "stanza-upgrade"
#define CFGCMD_START                                                "start"
#define CFGCMD_STOP                                                 "stop"
#define CFGCMD_VERIFY                                               "verify"
#define CFGCMD_VERSION                                              "version"

#define CFG_COMMAND_TOTAL                                           24

/***********************************************************************************************************************************
Option group constants
***********************************************************************************************************************************/
#define CFG_OPTION_GROUP_TOTAL                                      2

/***********************************************************************************************************************************
Option constants
***********************************************************************************************************************************/
#define CFGOPT_ANNOTATION                                           "annotation"
#define CFGOPT_ARCHIVE_ASYNC                                        "archive-async"
#define CFGOPT_ARCHIVE_CHECK                                        "archive-check"
#define CFGOPT_ARCHIVE_COPY                                         "archive-copy"
#define CFGOPT_ARCHIVE_GET_QUEUE_MAX                                "archive-get-queue-max"
#define CFGOPT_ARCHIVE_HEADER_CHECK                                 "archive-header-check"
#define CFGOPT_ARCHIVE_MISSING_RETRY                                "archive-missing-retry"
#define CFGOPT_ARCHIVE_MODE                                         "archive-mode"
#define CFGOPT_ARCHIVE_MODE_CHECK                                   "archive-mode-check"
#define CFGOPT_ARCHIVE_PUSH_QUEUE_MAX                               "archive-push-queue-max"
#define CFGOPT_ARCHIVE_TIMEOUT                                      "archive-timeout"
#define CFGOPT_BACKUP_STANDBY                                       "backup-standby"
#define CFGOPT_BETA                                                 "beta"
#define CFGOPT_BUFFER_SIZE                                          "buffer-size"
#define CFGOPT_CHECKSUM_PAGE                                        "checksum-page"
#define CFGOPT_CIPHER_PASS                                          "cipher-pass"
#define CFGOPT_CMD                                                  "cmd"
#define CFGOPT_CMD_SSH                                              "cmd-ssh"
#define CFGOPT_COMPRESS                                             "compress"
#define CFGOPT_COMPRESS_LEVEL                                       "compress-level"
#define CFGOPT_COMPRESS_LEVEL_NETWORK                               "compress-level-network"
#define CFGOPT_COMPRESS_TYPE                                        "compress-type"
#define CFGOPT_CONFIG                                               "config"
#define CFGOPT_CONFIG_INCLUDE_PATH                                  "config-include-path"
#define CFGOPT_CONFIG_PATH                                          "config-path"
#define CFGOPT_DB_EXCLUDE                                           "db-exclude"
#define CFGOPT_DB_INCLUDE                                           "db-include"
#define CFGOPT_DB_TIMEOUT                                           "db-timeout"
#define CFGOPT_DELTA                                                "delta"
#define CFGOPT_DRY_RUN                                              "dry-run"
#define CFGOPT_EXCLUDE                                              "exclude"
#define CFGOPT_EXEC_ID                                              "exec-id"
#define CFGOPT_EXPIRE_AUTO                                          "expire-auto"
#define CFGOPT_FILTER                                               "filter"
#define CFGOPT_FORCE                                                "force"
#define CFGOPT_IGNORE_MISSING                                       "ignore-missing"
#define CFGOPT_IO_TIMEOUT                                           "io-timeout"
#define CFGOPT_JOB_RETRY                                            "job-retry"
#define CFGOPT_JOB_RETRY_INTERVAL                                   "job-retry-interval"
#define CFGOPT_LINK_ALL                                             "link-all"
#define CFGOPT_LINK_MAP                                             "link-map"
#define CFGOPT_LOCK_PATH                                            "lock-path"
#define CFGOPT_LOG_LEVEL_CONSOLE                                    "log-level-console"
#define CFGOPT_LOG_LEVEL_FILE                                       "log-level-file"
#define CFGOPT_LOG_LEVEL_STDERR                                     "log-level-stderr"
#define CFGOPT_LOG_PATH                                             "log-path"
#define CFGOPT_LOG_SUBPROCESS                                       "log-subprocess"
#define CFGOPT_LOG_TIMESTAMP                                        "log-timestamp"
#define CFGOPT_MANIFEST_SAVE_THRESHOLD                              "manifest-save-threshold"
#define CFGOPT_NEUTRAL_UMASK                                        "neutral-umask"
#define CFGOPT_ONLINE                                               "online"
#define CFGOPT_OUTPUT                                               "output"
#define CFGOPT_PAGE_HEADER_CHECK                                    "page-header-check"
#define CFGOPT_PG                                                   "pg"
#define CFGOPT_PG_VERSION_FORCE                                     "pg-version-force"
#define CFGOPT_PROCESS                                              "process"
#define CFGOPT_PROCESS_MAX                                          "process-max"
#define CFGOPT_PROTOCOL_TIMEOUT                                     "protocol-timeout"
#define CFGOPT_RAW                                                  "raw"
#define CFGOPT_RECOVERY_OPTION                                      "recovery-option"
#define CFGOPT_RECURSE                                              "recurse"
#define CFGOPT_REFERENCE                                            "reference"
#define CFGOPT_REMOTE_TYPE                                          "remote-type"
#define CFGOPT_REPO                                                 "repo"
#define CFGOPT_REPORT                                               "report"
#define CFGOPT_RESUME                                               "resume"
#define CFGOPT_SCK_BLOCK                                            "sck-block"
#define CFGOPT_SCK_KEEP_ALIVE                                       "sck-keep-alive"
#define CFGOPT_SET                                                  "set"
#define CFGOPT_SORT                                                 "sort"
#define CFGOPT_SPOOL_PATH                                           "spool-path"
#define CFGOPT_STANZA                                               "stanza"
#define CFGOPT_START_FAST                                           "start-fast"
#define CFGOPT_STOP_AUTO                                            "stop-auto"
#define CFGOPT_TABLESPACE_MAP                                       "tablespace-map"
#define CFGOPT_TABLESPACE_MAP_ALL                                   "tablespace-map-all"
#define CFGOPT_TARGET                                               "target"
#define CFGOPT_TARGET_ACTION                                        "target-action"
#define CFGOPT_TARGET_EXCLUSIVE                                     "target-exclusive"
#define CFGOPT_TARGET_TIMELINE                                      "target-timeline"
#define CFGOPT_TCP_KEEP_ALIVE_COUNT                                 "tcp-keep-alive-count"
#define CFGOPT_TCP_KEEP_ALIVE_IDLE                                  "tcp-keep-alive-idle"
#define CFGOPT_TCP_KEEP_ALIVE_INTERVAL                              "tcp-keep-alive-interval"
#define CFGOPT_TLS_SERVER_ADDRESS                                   "tls-server-address"
#define CFGOPT_TLS_SERVER_AUTH                                      "tls-server-auth"
#define CFGOPT_TLS_SERVER_CA_FILE                                   "tls-server-ca-file"
#define CFGOPT_TLS_SERVER_CERT_FILE                                 "tls-server-cert-file"
#define CFGOPT_TLS_SERVER_KEY_FILE                                  "tls-server-key-file"
#define CFGOPT_TLS_SERVER_PORT                                      "tls-server-port"
#define CFGOPT_TYPE                                                 "type"
#define CFGOPT_VERBOSE                                              "verbose"

#define CFG_OPTION_TOTAL                                            181

/***********************************************************************************************************************************
Option value constants
***********************************************************************************************************************************/
#define CFGOPTVAL_ARCHIVE_MODE_OFF                                  STRID5("off", 0x18cf0)
#define CFGOPTVAL_ARCHIVE_MODE_OFF_Z                                "off"
#define CFGOPTVAL_ARCHIVE_MODE_PRESERVE                             STRID5("preserve", 0x2da45996500)
#define CFGOPTVAL_ARCHIVE_MODE_PRESERVE_Z                           "preserve"

#define CFGOPTVAL_COMPRESS_TYPE_BZ2                                 STRID5("bz2", 0x73420)
#define CFGOPTVAL_COMPRESS_TYPE_BZ2_Z                               "bz2"
#define CFGOPTVAL_COMPRESS_TYPE_GZ                                  STRID5("gz", 0x3470)
#define CFGOPTVAL_COMPRESS_TYPE_GZ_Z                                "gz"
#define CFGOPTVAL_COMPRESS_TYPE_LZ4                                 STRID6("lz4", 0x2068c1)
#define CFGOPTVAL_COMPRESS_TYPE_LZ4_Z                               "lz4"
#define CFGOPTVAL_COMPRESS_TYPE_NONE                                STRID5("none", 0x2b9ee0)
#define CFGOPTVAL_COMPRESS_TYPE_NONE_Z                              "none"
#define CFGOPTVAL_COMPRESS_TYPE_ZST                                 STRID5("zst", 0x527a0)
#define CFGOPTVAL_COMPRESS_TYPE_ZST_Z                               "zst"

#define CFGOPTVAL_LOG_LEVEL_CONSOLE_DEBUG                           STRID5("debug", 0x7a88a40)
#define CFGOPTVAL_LOG_LEVEL_CONSOLE_DEBUG_Z                         "debug"
#define CFGOPTVAL_LOG_LEVEL_CONSOLE_DETAIL                          STRID5("detail", 0x1890d0a40)
#define CFGOPTVAL_LOG_LEVEL_CONSOLE_DETAIL_Z                        "detail"
#define CFGOPTVAL_LOG_LEVEL_CONSOLE_ERROR                           STRID5("error", 0x127ca450)
#define CFGOPTVAL_LOG_LEVEL_CONSOLE_ERROR_Z                         "error"
#define CFGOPTVAL_LOG_LEVEL_CONSOLE_INFO                            STRID5("info", 0x799c90)
#define CFGOPTVAL_LOG_LEVEL_CONSOLE_INFO_Z                          "info"
#define CFGOPTVAL_LOG_LEVEL_CONSOLE_OFF                             STRID5("off", 0x18cf0)
#define CFGOPTVAL_LOG_LEVEL_CONSOLE_OFF_Z                           "off"
#define CFGOPTVAL_LOG_LEVEL_CONSOLE_TRACE                           STRID5("trace", 0x5186540)
#define CFGOPTVAL_LOG_LEVEL_CONSOLE_TRACE_Z                         "trace"
#define CFGOPTVAL_LOG_LEVEL_CONSOLE_WARN                            STRID5("warn", 0x748370)
#define CFGOPTVAL_LOG_LEVEL_CONSOLE_WARN_Z                          "warn"

#define CFGOPTVAL_LOG_LEVEL_FILE_DEBUG                              STRID5("debug", 0x7a88a40)
#define CFGOPTVAL_LOG_LEVEL_FILE_DEBUG_Z                            "debug"
#define CFGOPTVAL_LOG_LEVEL_FILE_DETAIL                             STRID5("detail", 0x1890d0a40)
#define CFGOPTVAL_LOG_LEVEL_FILE_DETAIL_Z                           "detail"
#define CFGOPTVAL_LOG_LEVEL_FILE_ERROR                              STRID5("error", 0x127ca450)
#define CFGOPTVAL_LOG_LEVEL_FILE_ERROR_Z                            "error"
#define CFGOPTVAL_LOG_LEVEL_FILE_INFO                               STRID5("info", 0x799c90)
#define CFGOPTVAL_LOG_LEVEL_FILE_INFO_Z                             "info"
#define CFGOPTVAL_LOG_LEVEL_FILE_OFF                                STRID5("off", 0x18cf0)
#define CFGOPTVAL_LOG_LEVEL_FILE_OFF_Z                              "off"
#define CFGOPTVAL_LOG_LEVEL_FILE_TRACE                              STRID5("trace", 0x5186540)
#define CFGOPTVAL_LOG_LEVEL_FILE_TRACE_Z                            "trace"
#define CFGOPTVAL_LOG_LEVEL_FILE_WARN                               STRID5("warn", 0x748370)
#define CFGOPTVAL_LOG_LEVEL_FILE_WARN_Z                             "warn"

#define CFGOPTVAL_LOG_LEVEL_STDERR_DEBUG                            STRID5("debug", 0x7a88a40)
#define CFGOPTVAL_LOG_LEVEL_STDERR_DEBUG_Z                          "debug"
#define CFGOPTVAL_LOG_LEVEL_STDERR_DETAIL                           STRID5("detail", 0x1890d0a40)
#define CFGOPTVAL_LOG_LEVEL_STDERR_DETAIL_Z                         "detail"
#define CFGOPTVAL_LOG_LEVEL_STDERR_ERROR                            STRID5("error", 0x127ca450)
#define CFGOPTVAL_LOG_LEVEL_STDERR_ERROR_Z                          "error"
#define CFGOPTVAL_LOG_LEVEL_STDERR_INFO                             STRID5("info", 0x799c90)
#define CFGOPTVAL_LOG_LEVEL_STDERR_INFO_Z                           "info"
#define CFGOPTVAL_LOG_LEVEL_STDERR_OFF                              STRID5("off", 0x18cf0)
#define CFGOPTVAL_LOG_LEVEL_STDERR_OFF_Z                            "off"
#define CFGOPTVAL_LOG_LEVEL_STDERR_TRACE                            STRID5("trace", 0x5186540)
#define CFGOPTVAL_LOG_LEVEL_STDERR_TRACE_Z                          "trace"
#define CFGOPTVAL_LOG_LEVEL_STDERR_WARN                             STRID5("warn", 0x748370)
#define CFGOPTVAL_LOG_LEVEL_STDERR_WARN_Z                           "warn"

#define CFGOPTVAL_OUTPUT_JSON                                       STRID5("json", 0x73e6a0)
#define CFGOPTVAL_OUTPUT_JSON_Z                                     "json"
#define CFGOPTVAL_OUTPUT_NONE                                       STRID5("none", 0x2b9ee0)
#define CFGOPTVAL_OUTPUT_NONE_Z                                     "none"
#define CFGOPTVAL_OUTPUT_TEXT                                       STRID5("text", 0xa60b40)
#define CFGOPTVAL_OUTPUT_TEXT_Z                                     "text"

#define CFGOPTVAL_PG_HOST_TYPE_SSH                                  STRID5("ssh", 0x22730)
#define CFGOPTVAL_PG_HOST_TYPE_SSH_Z                                "ssh"
#define CFGOPTVAL_PG_HOST_TYPE_TLS                                  STRID5("tls", 0x4d940)
#define CFGOPTVAL_PG_HOST_TYPE_TLS_Z                                "tls"

#define CFGOPTVAL_REMOTE_TYPE_PG                                    STRID5("pg", 0xf00)
#define CFGOPTVAL_REMOTE_TYPE_PG_Z                                  "pg"
#define CFGOPTVAL_REMOTE_TYPE_REPO                                  STRID5("repo", 0x7c0b20)
#define CFGOPTVAL_REMOTE_TYPE_REPO_Z                                "repo"

#define CFGOPTVAL_REPO_AZURE_KEY_TYPE_SAS                           STRID5("sas", 0x4c330)
#define CFGOPTVAL_REPO_AZURE_KEY_TYPE_SAS_Z                         "sas"
#define CFGOPTVAL_REPO_AZURE_KEY_TYPE_SHARED                        STRID5("shared", 0x85905130)
#define CFGOPTVAL_REPO_AZURE_KEY_TYPE_SHARED_Z                      "shared"

#define CFGOPTVAL_REPO_AZURE_URI_STYLE_HOST                         STRID5("host", 0xa4de80)
#define CFGOPTVAL_REPO_AZURE_URI_STYLE_HOST_Z                       "host"
#define CFGOPTVAL_REPO_AZURE_URI_STYLE_PATH                         STRID5("path", 0x450300)
#define CFGOPTVAL_REPO_AZURE_URI_STYLE_PATH_Z                       "path"

#define CFGOPTVAL_REPO_CIPHER_TYPE_AES_256_CBC                      STRID5("aes-256-cbc", 0xc43dfbbcdcca10)
#define CFGOPTVAL_REPO_CIPHER_TYPE_AES_256_CBC_Z                    "aes-256-cbc"
#define CFGOPTVAL_REPO_CIPHER_TYPE_NONE                             STRID5("none", 0x2b9ee0)
#define CFGOPTVAL_REPO_CIPHER_TYPE_NONE_Z                           "none"

#define CFGOPTVAL_REPO_GCS_KEY_TYPE_AUTO                            STRID5("auto", 0x7d2a10)
#define CFGOPTVAL_REPO_GCS_KEY_TYPE_AUTO_Z                          "auto"
#define CFGOPTVAL_REPO_GCS_KEY_TYPE_SERVICE                         STRID5("service", 0x1469b48b30)
#define CFGOPTVAL_REPO_GCS_KEY_TYPE_SERVICE_Z                       "service"
#define CFGOPTVAL_REPO_GCS_KEY_TYPE_TOKEN                           STRID5("token", 0xe2adf40)
#define CFGOPTVAL_REPO_GCS_KEY_TYPE_TOKEN_Z                         "token"

#define CFGOPTVAL_REPO_HOST_TYPE_SSH                                STRID5("ssh", 0x22730)
#define CFGOPTVAL_REPO_HOST_TYPE_SSH_Z                              "ssh"
#define CFGOPTVAL_REPO_HOST_TYPE_TLS                                STRID5("tls", 0x4d940)
#define CFGOPTVAL_REPO_HOST_TYPE_TLS_Z                              "tls"

#define CFGOPTVAL_REPO_RETENTION_ARCHIVE_TYPE_DIFF                  STRID5("diff", 0x319240)
#define CFGOPTVAL_REPO_RETENTION_ARCHIVE_TYPE_DIFF_Z                "diff"
#define CFGOPTVAL_REPO_RETENTION_ARCHIVE_TYPE_FULL                  STRID5("full", 0x632a60)
#define CFGOPTVAL_REPO_RETENTION_ARCHIVE_TYPE_FULL_Z                "full"
#define CFGOPTVAL_REPO_RETENTION_ARCHIVE_TYPE_INCR                  STRID5("incr", 0x90dc90)
#define CFGOPTVAL_REPO_RETENTION_ARCHIVE_TYPE_INCR_Z                "incr"

#define CFGOPTVAL_REPO_RETENTION_FULL_TYPE_COUNT                    STRID5("count", 0x14755e30)
#define CFGOPTVAL_REPO_RETENTION_FULL_TYPE_COUNT_Z                  "count"
#define CFGOPTVAL_REPO_RETENTION_FULL_TYPE_TIME                     STRID5("time", 0x2b5340)
#define CFGOPTVAL_REPO_RETENTION_FULL_TYPE_TIME_Z                   "time"

#define CFGOPTVAL_REPO_S3_KEY_TYPE_AUTO                             STRID5("auto", 0x7d2a10)
#define CFGOPTVAL_REPO_S3_KEY_TYPE_AUTO_Z                           "auto"
#define CFGOPTVAL_REPO_S3_KEY_TYPE_SHARED                           STRID5("shared", 0x85905130)
#define CFGOPTVAL_REPO_S3_KEY_TYPE_SHARED_Z                         "shared"
#define CFGOPTVAL_REPO_S3_KEY_TYPE_WEB_ID                           STRID5("web-id", 0x89d88b70)
#define CFGOPTVAL_REPO_S3_KEY_TYPE_WEB_ID_Z                         "web-id"

#define CFGOPTVAL_REPO_S3_URI_STYLE_HOST                            STRID5("host", 0xa4de80)
#define CFGOPTVAL_REPO_S3_URI_STYLE_HOST_Z                          "host"
#define CFGOPTVAL_REPO_S3_URI_STYLE_PATH                            STRID5("path", 0x450300)
#define CFGOPTVAL_REPO_S3_URI_STYLE_PATH_Z                          "path"

#define CFGOPTVAL_REPO_SFTP_HOST_KEY_CHECK_TYPE_ACCEPT_NEW          STRID5("accept-new", 0x2e576e9028c610)
#define CFGOPTVAL_REPO_SFTP_HOST_KEY_CHECK_TYPE_ACCEPT_NEW_Z        "accept-new"
#define CFGOPTVAL_REPO_SFTP_HOST_KEY_CHECK_TYPE_FINGERPRINT         STRID5("fingerprint", 0x51c9942453b9260)
#define CFGOPTVAL_REPO_SFTP_HOST_KEY_CHECK_TYPE_FINGERPRINT_Z       "fingerprint"
#define CFGOPTVAL_REPO_SFTP_HOST_KEY_CHECK_TYPE_NONE                STRID5("none", 0x2b9ee0)
#define CFGOPTVAL_REPO_SFTP_HOST_KEY_CHECK_TYPE_NONE_Z              "none"
#define CFGOPTVAL_REPO_SFTP_HOST_KEY_CHECK_TYPE_STRICT              STRID5("strict", 0x2834ca930)
#define CFGOPTVAL_REPO_SFTP_HOST_KEY_CHECK_TYPE_STRICT_Z            "strict"

#define CFGOPTVAL_REPO_SFTP_HOST_KEY_HASH_TYPE_MD5                  STRID5("md5", 0x748d0)
#define CFGOPTVAL_REPO_SFTP_HOST_KEY_HASH_TYPE_MD5_Z                "md5"
#define CFGOPTVAL_REPO_SFTP_HOST_KEY_HASH_TYPE_SHA1                 STRID6("sha1", 0x7412131)
#define CFGOPTVAL_REPO_SFTP_HOST_KEY_HASH_TYPE_SHA1_Z               "sha1"
#define CFGOPTVAL_REPO_SFTP_HOST_KEY_HASH_TYPE_SHA256               STRID5("sha256", 0x3dde05130)
#define CFGOPTVAL_REPO_SFTP_HOST_KEY_HASH_TYPE_SHA256_Z             "sha256"

#define CFGOPTVAL_REPO_TYPE_AZURE                                   STRID5("azure", 0x5957410)
#define CFGOPTVAL_REPO_TYPE_AZURE_Z                                 "azure"
#define CFGOPTVAL_REPO_TYPE_CIFS                                    STRID5("cifs", 0x999230)
#define CFGOPTVAL_REPO_TYPE_CIFS_Z                                  "cifs"
#define CFGOPTVAL_REPO_TYPE_GCS                                     STRID5("gcs", 0x4c670)
#define CFGOPTVAL_REPO_TYPE_GCS_Z                                   "gcs"
#define CFGOPTVAL_REPO_TYPE_POSIX                                   STRID5("posix", 0x184cdf00)
#define CFGOPTVAL_REPO_TYPE_POSIX_Z                                 "posix"
#define CFGOPTVAL_REPO_TYPE_S3                                      STRID6("s3", 0x7d31)
#define CFGOPTVAL_REPO_TYPE_S3_Z                                    "s3"
#define CFGOPTVAL_REPO_TYPE_SFTP                                    STRID5("sftp", 0x850d30)
#define CFGOPTVAL_REPO_TYPE_SFTP_Z                                  "sftp"

#define CFGOPTVAL_SORT_ASC                                          STRID5("asc", 0xe610)
#define CFGOPTVAL_SORT_ASC_Z                                        "asc"
#define CFGOPTVAL_SORT_DESC                                         STRID5("desc", 0x1cca40)
#define CFGOPTVAL_SORT_DESC_Z                                       "desc"
#define CFGOPTVAL_SORT_NONE                                         STRID5("none", 0x2b9ee0)
#define CFGOPTVAL_SORT_NONE_Z                                       "none"

#define CFGOPTVAL_TARGET_ACTION_PAUSE                               STRID5("pause", 0x59d4300)
#define CFGOPTVAL_TARGET_ACTION_PAUSE_Z                             "pause"
#define CFGOPTVAL_TARGET_ACTION_PROMOTE                             STRID5("promote", 0x168f6be500)
#define CFGOPTVAL_TARGET_ACTION_PROMOTE_Z                           "promote"
#define CFGOPTVAL_TARGET_ACTION_SHUTDOWN                            STRID5("shutdown", 0x75de4a55130)
#define CFGOPTVAL_TARGET_ACTION_SHUTDOWN_Z                          "shutdown"

#define CFGOPTVAL_TYPE_DEFAULT                                      STRID5("default", 0x5195098a40)
#define CFGOPTVAL_TYPE_DEFAULT_Z                                    "default"
#define CFGOPTVAL_TYPE_DIFF                                         STRID5("diff", 0x319240)
#define CFGOPTVAL_TYPE_DIFF_Z                                       "diff"
#define CFGOPTVAL_TYPE_FULL                                         STRID5("full", 0x632a60)
#define CFGOPTVAL_TYPE_FULL_Z                                       "full"
#define CFGOPTVAL_TYPE_IMMEDIATE                                    STRID5("immediate", 0x5a05242b5a90)
#define CFGOPTVAL_TYPE_IMMEDIATE_Z                                  "immediate"
#define CFGOPTVAL_TYPE_INCR                                         STRID5("incr", 0x90dc90)
#define CFGOPTVAL_TYPE_INCR_Z                                       "incr"
#define CFGOPTVAL_TYPE_LSN                                          STRID5("lsn", 0x3a6c0)
#define CFGOPTVAL_TYPE_LSN_Z                                        "lsn"
#define CFGOPTVAL_TYPE_NAME                                         STRID5("name", 0x2b42e0)
#define CFGOPTVAL_TYPE_NAME_Z                                       "name"
#define CFGOPTVAL_TYPE_NONE                                         STRID5("none", 0x2b9ee0)
#define CFGOPTVAL_TYPE_NONE_Z                                       "none"
#define CFGOPTVAL_TYPE_PRESERVE                                     STRID5("preserve", 0x2da45996500)
#define CFGOPTVAL_TYPE_PRESERVE_Z                                   "preserve"
#define CFGOPTVAL_TYPE_STANDBY                                      STRID5("standby", 0x6444706930)
#define CFGOPTVAL_TYPE_STANDBY_Z                                    "standby"
#define CFGOPTVAL_TYPE_TIME                                         STRID5("time", 0x2b5340)
#define CFGOPTVAL_TYPE_TIME_Z                                       "time"
#define CFGOPTVAL_TYPE_XID                                          STRID5("xid", 0x11380)
#define CFGOPTVAL_TYPE_XID_Z                                        "xid"

/***********************************************************************************************************************************
Command enum
***********************************************************************************************************************************/
typedef enum
{
    cfgCmdAnnotate,
    cfgCmdArchiveGet,
    cfgCmdArchivePush,
    cfgCmdBackup,
    cfgCmdCheck,
    cfgCmdExpire,
    cfgCmdHelp,
    cfgCmdInfo,
    cfgCmdManifest,
    cfgCmdRepoCreate,
    cfgCmdRepoGet,
    cfgCmdRepoLs,
    cfgCmdRepoPut,
    cfgCmdRepoRm,
    cfgCmdRestore,
    cfgCmdServer,
    cfgCmdServerPing,
    cfgCmdStanzaCreate,
    cfgCmdStanzaDelete,
    cfgCmdStanzaUpgrade,
    cfgCmdStart,
    cfgCmdStop,
    cfgCmdVerify,
    cfgCmdVersion,
    cfgCmdNone,
} ConfigCommand;

/***********************************************************************************************************************************
Option group enum
***********************************************************************************************************************************/
typedef enum
{
    cfgOptGrpPg,
    cfgOptGrpRepo,
} ConfigOptionGroup;

/***********************************************************************************************************************************
Option enum
***********************************************************************************************************************************/
typedef enum
{
    cfgOptAnnotation,
    cfgOptArchiveAsync,
    cfgOptArchiveCheck,
    cfgOptArchiveCopy,
    cfgOptArchiveGetQueueMax,
    cfgOptArchiveHeaderCheck,
    cfgOptArchiveMissingRetry,
    cfgOptArchiveMode,
    cfgOptArchiveModeCheck,
    cfgOptArchivePushQueueMax,
    cfgOptArchiveTimeout,
    cfgOptBackupStandby,
    cfgOptBeta,
    cfgOptBufferSize,
    cfgOptChecksumPage,
    cfgOptCipherPass,
    cfgOptCmd,
    cfgOptCmdSsh,
    cfgOptCompress,
    cfgOptCompressLevel,
    cfgOptCompressLevelNetwork,
    cfgOptCompressType,
    cfgOptConfig,
    cfgOptConfigIncludePath,
    cfgOptConfigPath,
    cfgOptDbExclude,
    cfgOptDbInclude,
    cfgOptDbTimeout,
    cfgOptDelta,
    cfgOptDryRun,
    cfgOptExclude,
    cfgOptExecId,
    cfgOptExpireAuto,
    cfgOptFilter,
    cfgOptForce,
    cfgOptIgnoreMissing,
    cfgOptIoTimeout,
    cfgOptJobRetry,
    cfgOptJobRetryInterval,
    cfgOptLinkAll,
    cfgOptLinkMap,
    cfgOptLockPath,
    cfgOptLogLevelConsole,
    cfgOptLogLevelFile,
    cfgOptLogLevelStderr,
    cfgOptLogPath,
    cfgOptLogSubprocess,
    cfgOptLogTimestamp,
    cfgOptManifestSaveThreshold,
    cfgOptNeutralUmask,
    cfgOptOnline,
    cfgOptOutput,
    cfgOptPageHeaderCheck,
    cfgOptPg,
    cfgOptPgDatabase,
    cfgOptPgHost,
    cfgOptPgHostCaFile,
    cfgOptPgHostCaPath,
    cfgOptPgHostCertFile,
    cfgOptPgHostCmd,
    cfgOptPgHostConfig,
    cfgOptPgHostConfigIncludePath,
    cfgOptPgHostConfigPath,
    cfgOptPgHostKeyFile,
    cfgOptPgHostPort,
    cfgOptPgHostType,
    cfgOptPgHostUser,
    cfgOptPgLocal,
    cfgOptPgPath,
    cfgOptPgPort,
    cfgOptPgSocketPath,
    cfgOptPgUser,
    cfgOptPgVersionForce,
    cfgOptProcess,
    cfgOptProcessMax,
    cfgOptProtocolTimeout,
    cfgOptRaw,
    cfgOptRecoveryOption,
    cfgOptRecurse,
    cfgOptReference,
    cfgOptRemoteType,
    cfgOptRepo,
    cfgOptRepoAzureAccount,
    cfgOptRepoAzureContainer,
    cfgOptRepoAzureEndpoint,
    cfgOptRepoAzureKey,
    cfgOptRepoAzureKeyType,
    cfgOptRepoAzureUriStyle,
    cfgOptRepoBlock,
    cfgOptRepoBlockAgeMap,
    cfgOptRepoBlockChecksumSizeMap,
    cfgOptRepoBlockSizeMap,
    cfgOptRepoBlockSizeSuper,
    cfgOptRepoBlockSizeSuperFull,
    cfgOptRepoBundle,
    cfgOptRepoBundleLimit,
    cfgOptRepoBundleSize,
    cfgOptRepoCipherPass,
    cfgOptRepoCipherType,
    cfgOptRepoGcsBucket,
    cfgOptRepoGcsEndpoint,
    cfgOptRepoGcsKey,
    cfgOptRepoGcsKeyType,
    cfgOptRepoHardlink,
    cfgOptRepoHost,
    cfgOptRepoHostCaFile,
    cfgOptRepoHostCaPath,
    cfgOptRepoHostCertFile,
    cfgOptRepoHostCmd,
    cfgOptRepoHostConfig,
    cfgOptRepoHostConfigIncludePath,
    cfgOptRepoHostConfigPath,
    cfgOptRepoHostKeyFile,
    cfgOptRepoHostPort,
    cfgOptRepoHostType,
    cfgOptRepoHostUser,
    cfgOptRepoLocal,
    cfgOptRepoPath,
    cfgOptRepoRetentionArchive,
    cfgOptRepoRetentionArchiveType,
    cfgOptRepoRetentionDiff,
    cfgOptRepoRetentionFull,
    cfgOptRepoRetentionFullType,
    cfgOptRepoRetentionHistory,
    cfgOptRepoS3Bucket,
    cfgOptRepoS3Endpoint,
    cfgOptRepoS3Key,
    cfgOptRepoS3KeySecret,
    cfgOptRepoS3KeyType,
    cfgOptRepoS3KmsKeyId,
    cfgOptRepoS3Region,
    cfgOptRepoS3Role,
    cfgOptRepoS3Token,
    cfgOptRepoS3UriStyle,
    cfgOptRepoSftpHost,
    cfgOptRepoSftpHostFingerprint,
    cfgOptRepoSftpHostKeyCheckType,
    cfgOptRepoSftpHostKeyHashType,
    cfgOptRepoSftpHostPort,
    cfgOptRepoSftpHostUser,
    cfgOptRepoSftpIdentityAgent,
    cfgOptRepoSftpKnownHost,
    cfgOptRepoSftpPrivateKeyFile,
    cfgOptRepoSftpPrivateKeyPassphrase,
    cfgOptRepoSftpPublicKeyFile,
    cfgOptRepoSftpUseSshAgent,
    cfgOptRepoStorageCaFile,
    cfgOptRepoStorageCaPath,
    cfgOptRepoStorageHost,
    cfgOptRepoStoragePort,
    cfgOptRepoStorageTag,
    cfgOptRepoStorageUploadChunkSize,
    cfgOptRepoStorageVerifyTls,
    cfgOptRepoType,
    cfgOptReport,
    cfgOptResume,
    cfgOptSckBlock,
    cfgOptSckKeepAlive,
    cfgOptSet,
    cfgOptSort,
    cfgOptSpoolPath,
    cfgOptStanza,
    cfgOptStartFast,
    cfgOptStopAuto,
    cfgOptTablespaceMap,
    cfgOptTablespaceMapAll,
    cfgOptTarget,
    cfgOptTargetAction,
    cfgOptTargetExclusive,
    cfgOptTargetTimeline,
    cfgOptTcpKeepAliveCount,
    cfgOptTcpKeepAliveIdle,
    cfgOptTcpKeepAliveInterval,
    cfgOptTlsServerAddress,
    cfgOptTlsServerAuth,
    cfgOptTlsServerCaFile,
    cfgOptTlsServerCertFile,
    cfgOptTlsServerKeyFile,
    cfgOptTlsServerPort,
    cfgOptType,
    cfgOptVerbose,
} ConfigOption;

#endif
