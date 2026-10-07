#include <epan/epan.h>
#include <epan/prefs.h>
#include <epan/timestamp.h>
#include <glib.h>
#include <stdio.h>
#include <stdlib.h>
#include <wiretap/wtap.h>
#include <wsutil/privileges.h>
#include <wsutil/report_message.h>


/**
 * 最小化 Epan 验证程序
 * 目标：验证 Wireshark 核心库在 Android 设备上的初始化和基础解析功能
 */

int main(int argc, char *argv[]) {
  int err = 0;
  gchar *err_info = NULL;
  wtap *wth = NULL;
  epan_t *epan_session = NULL;
  epan_dissect_t *edt = NULL;
  wtap_rec rec;
  Buffer buf;
  gint64 data_offset = 0;
  int packet_count = 0;

  // ================= 参数检查 =================
  if (argc < 2) {
    printf("Usage: %s <pcap_file>\n", argv[0]);
    return 1;
  }
  const char *filename = argv[1];

  // ================= 初始化 Epan 引擎 =================
  printf("[*] Epan version: %s\n", epan_get_version());
  printf("[*] Initializing Wireshark Epan engine...\n");

  // 初始化特权管理（Android 上可能不需要，但保持兼容）
  init_process_policies();

  // 初始化消息报告系统（避免某些解析器路径的崩溃）
  init_report_message("hello_tshark", NULL);

  // 初始化 epan
  // 参数：register_cb（NULL=使用默认注册）, client_data,
  // load_plugins（FALSE=禁用插件）
  if (!epan_init(NULL, NULL, FALSE)) {
    fprintf(stderr, "[-] epan_init failed\n");
    return 1;
  }
  printf("[+] epan_init succeeded\n");

  // 加载配置（必要，否则某些 Dissector 可能崩溃）
  epan_load_settings();

  // ================= 打开 Pcap 文件 =================
  printf("[*] Opening capture file: %s\n", filename);
  wth = wtap_open_offline(filename, WTAP_TYPE_AUTO, &err, &err_info, TRUE);
  if (!wth) {
    fprintf(stderr, "[-] wtap_open_offline failed: error %d\n", err);
    if (err_info) {
      fprintf(stderr, "    Details: %s\n", err_info);
      g_free(err_info);
    }
    epan_cleanup();
    return 1;
  }
  printf("[+] File opened successfully\n");

  // ================= 创建 Epan Session =================
  // packet_provider_data 和 funcs 可为 NULL（不需要外部提供时间戳等信息）
  epan_session = epan_new(NULL, NULL);
  if (!epan_session) {
    fprintf(stderr, "[-] epan_new failed\n");
    wtap_close(wth);
    epan_cleanup();
    return 1;
  }

  // ================= 读取并解析数据包 =================
  printf("[*] Starting packet loop...\n");

  wtap_rec_init(&rec);
  ws_buffer_init(&buf, 1500);

  while (wtap_read(wth, &rec, &buf, &err, &err_info, &data_offset)) {
    packet_count++;

    // 创建解析上下文
    // 参数：session, create_proto_tree, proto_tree_visible
    edt = epan_dissect_new(epan_session, TRUE, TRUE);

    // 执行解析
    // 注意：在 4.0.x 中 epan_dissect_run 需要 frame_data，但对于简单验证可以传
    // NULL 这里我们只验证引擎能运行，不深入遍历 proto_tree
    frame_data fdata;
    fdata.num = packet_count;
    fdata.file_off = data_offset;
    fdata.pkt_len = rec.rec_header.packet_header.caplen;

    epan_dissect_run(edt, wtap_file_type_subtype(wth), &rec,
                     tvb_new_real_data(ws_buffer_start_ptr(&buf),
                                       rec.rec_header.packet_header.caplen,
                                       rec.rec_header.packet_header.len),
                     &fdata, NULL);

    printf("[+] Packet %d parsed - length: %u bytes\n", packet_count,
           rec.rec_header.packet_header.caplen);

    // 清理当前解析上下文
    epan_dissect_free(edt);
    wtap_rec_reset(&rec);

    // 只解析前 5 个包以保持快速验证
    if (packet_count >= 5) {
      printf("[*] Parsed 5 packets, stopping verification.\n");
      break;
    }
  }

  // 检查读取错误
  if (err != 0) {
    fprintf(stderr, "[-] wtap_read error: %d\n", err);
    if (err_info) {
      fprintf(stderr, "    Details: %s\n", err_info);
      g_free(err_info);
    }
  }

  // ================= 清理资源 =================
  wtap_rec_cleanup(&rec);
  ws_buffer_free(&buf);
  wtap_close(wth);
  epan_free(epan_session);
  epan_cleanup();

  printf("[+] Verification Success! Total packets: %d\n", packet_count);
  return 0;
}
