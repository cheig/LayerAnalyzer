// HTTP export-object callbacks. The stream module installs them into a
// Wireshark export_object_list_t and the PerfExport debug path reuses the same
// callbacks so both paths collect identical HTTP object snapshots.
#pragma once
#include "layanalyzer/internal/Common.h"

void http_object_list_add_entry(void *gui_data,
                                export_object_entry_t *entry);
export_object_entry_t *http_object_list_get_entry(void *gui_data, int row);
