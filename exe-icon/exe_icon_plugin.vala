using GLib;
using Peas;

namespace Singularity.ExeIcon {

    private errordomain PeError {
        MALFORMED
    }

    public class ExeIconProvider : Object, Singularity.FileIconProvider {

        public bool matches(GLib.File file, string? content_type) {
            if (file.get_path() == null) return false;
            string name = file.get_basename() ?? "";
            if (name.down().has_suffix(".exe")) return true;
            if (content_type == null) return false;
            switch (content_type) {
                case "application/x-ms-dos-executable":
                case "application/x-msdownload":
                case "application/x-dosexec":
                case "application/vnd.microsoft.portable-executable":
                    return true;
                default:
                    return false;
            }
        }

        public async Gdk.Paintable? load_icon(GLib.File file, int size) {
            string? path = file.get_path();
            if (path == null) return null;

            int px = size > 0 ? size : 48;
            Gdk.Pixbuf? full = null;

            string? cache = cache_path_for(path);
            if (cache != null && FileUtils.test(cache, FileTest.EXISTS)) {
                try {
                    full = new Gdk.Pixbuf.from_file(cache);
                } catch (Error e) {
                    full = null;
                }
            }

            if (full == null) {
                try {
                    full = extract_pixbuf(path);
                } catch (Error e) {
                    return null;
                }
                if (full == null) return null;
                if (cache != null) {
                    try {
                        var dir = GLib.Path.get_dirname(cache);
                        var df = GLib.File.new_for_path(dir);
                        if (!df.query_exists()) df.make_directory_with_parents();
                        full.save(cache, "png");
                    } catch (Error e) { }
                }
            }

            Gdk.Pixbuf scaled = full;
            if (full.get_width() != px || full.get_height() != px) {
                var s = full.scale_simple(px, px, Gdk.InterpType.BILINEAR);
                if (s != null) scaled = s;
            }
            return Gdk.Texture.for_pixbuf(scaled);
        }

        private string? cache_path_for(string path) {
            try {
                var info = GLib.File.new_for_path(path).query_info(
                    "time::modified,standard::size", FileQueryInfoFlags.NONE);
                uint64 mtime = info.get_attribute_uint64("time::modified");
                int64 fsize = info.get_size();
                string key = "%s|%llu|%lld".printf(path, mtime, fsize);
                string hash = GLib.Checksum.compute_for_string(ChecksumType.MD5, key);
                return GLib.Path.build_filename(
                    Environment.get_user_cache_dir(),
                    "singularity-files", "exe-icons", hash + ".png");
            } catch (Error e) {
                return null;
            }
        }

        private static uint16 ru16(uint8[] d, uint off) throws PeError {
            if (off + 2 > d.length) throw new PeError.MALFORMED("u16 out of bounds");
            return (uint16) (d[off] | (d[off + 1] << 8));
        }

        private static uint32 ru32(uint8[] d, uint off) throws PeError {
            if (off + 4 > d.length) throw new PeError.MALFORMED("u32 out of bounds");
            return (uint32) (d[off] | (d[off + 1] << 8) | (d[off + 2] << 16) | (d[off + 3] << 24));
        }

        private static bool dir_lookup(uint8[] d, uint rsrc_ptr, uint dir_rel,
                bool match_first, uint32 target_id,
                out uint32 off_to_data, out bool is_subdir) throws PeError {
            off_to_data = 0;
            is_subdir = false;
            uint dir_off = rsrc_ptr + dir_rel;
            uint16 named = ru16(d, dir_off + 12);
            uint16 ids = ru16(d, dir_off + 14);
            uint total = named + ids;
            uint entries_off = dir_off + 16;
            for (uint i = 0; i < total; i++) {
                uint e = entries_off + i * 8;
                uint32 name = ru32(d, e);
                uint32 otd = ru32(d, e + 4);
                bool is_named = (name & 0x80000000) != 0;
                if (match_first || (!is_named && name == target_id)) {
                    off_to_data = otd & 0x7FFFFFFF;
                    is_subdir = (otd & 0x80000000) != 0;
                    return true;
                }
            }
            return false;
        }

        private static bool resolve_leaf(uint8[] d, uint rsrc_ptr, uint32 rsrc_va,
                uint32 leaf_rel, out uint data_foff, out uint32 data_size) throws PeError {
            data_foff = 0;
            data_size = 0;
            uint de = rsrc_ptr + leaf_rel;
            uint32 rva = ru32(d, de);
            uint32 size = ru32(d, de + 4);
            int64 foff = (int64) rva - (int64) rsrc_va + (int64) rsrc_ptr;
            if (foff < 0 || foff + size > d.length) return false;
            data_foff = (uint) foff;
            data_size = size;
            return true;
        }

        private Gdk.Pixbuf? extract_pixbuf(string path) throws Error {
            var mf = new GLib.MappedFile(path, false);
            var mbytes = mf.get_bytes();
            unowned uint8[] d = mbytes.get_data();
            if (d == null || d.length < 0x40) return null;

            if (d[0] != 'M' || d[1] != 'Z') return null;
            uint32 e_lfanew = ru32(d, 0x3C);
            if (e_lfanew + 24 > d.length) return null;
            if (ru32(d, e_lfanew) != 0x00004550) return null;

            uint16 num_sections = ru16(d, e_lfanew + 6);
            uint16 size_opt = ru16(d, e_lfanew + 20);
            uint sec_off = e_lfanew + 24 + size_opt;

            uint32 rsrc_va = 0;
            uint rsrc_ptr = 0;
            bool found = false;
            for (uint i = 0; i < num_sections; i++) {
                uint s = sec_off + i * 40;
                if (s + 40 > d.length) break;
                bool is_rsrc = d[s] == '.' && d[s + 1] == 'r' && d[s + 2] == 's'
                    && d[s + 3] == 'r' && d[s + 4] == 'c';
                if (is_rsrc) {
                    rsrc_va = ru32(d, s + 12);
                    rsrc_ptr = ru32(d, s + 20);
                    found = true;
                    break;
                }
            }
            if (!found || rsrc_ptr == 0) return null;

            uint32 sub14, grp_res, grp_leaf;
            bool issub;
            if (!dir_lookup(d, rsrc_ptr, 0, false, 14, out sub14, out issub) || !issub) return null;
            if (!dir_lookup(d, rsrc_ptr, sub14, true, 0, out grp_res, out issub) || !issub) return null;
            if (!dir_lookup(d, rsrc_ptr, grp_res, true, 0, out grp_leaf, out issub) || issub) return null;

            uint grp_foff;
            uint32 grp_size;
            if (!resolve_leaf(d, rsrc_ptr, rsrc_va, grp_leaf, out grp_foff, out grp_size)) return null;
            if (grp_size < 6) return null;

            uint16 count = ru16(d, grp_foff + 4);
            if (count == 0 || count > 64) return null;

            uint32 sub3;
            if (!dir_lookup(d, rsrc_ptr, 0, false, 3, out sub3, out issub) || !issub) return null;

            var body = new ByteArray();
            var dirents = new ByteArray();
            uint header_size = 6 + (uint) count * 16;
            uint running = header_size;

            uint16 real_count = 0;
            for (uint16 i = 0; i < count; i++) {
                uint ge = grp_foff + 6 + i * 14;
                if (ge + 14 > d.length) break;
                uint8 b_width = d[ge];
                uint8 b_height = d[ge + 1];
                uint8 b_colors = d[ge + 2];
                uint8 b_reserved = d[ge + 3];
                uint16 planes = ru16(d, ge + 4);
                uint16 bitcount = ru16(d, ge + 6);
                uint16 n_id = ru16(d, ge + 12);

                uint32 icon_res, icon_leaf;
                bool sb;
                if (!dir_lookup(d, rsrc_ptr, sub3, false, n_id, out icon_res, out sb) || !sb) continue;
                if (!dir_lookup(d, rsrc_ptr, icon_res, true, 0, out icon_leaf, out sb) || sb) continue;

                uint icon_foff;
                uint32 icon_size;
                if (!resolve_leaf(d, rsrc_ptr, rsrc_va, icon_leaf, out icon_foff, out icon_size)) continue;
                if (icon_size == 0) continue;

                uint8 de_buf[16];
                de_buf[0] = b_width;
                de_buf[1] = b_height;
                de_buf[2] = b_colors;
                de_buf[3] = b_reserved;
                de_buf[4] = (uint8) (planes & 0xFF);
                de_buf[5] = (uint8) ((planes >> 8) & 0xFF);
                de_buf[6] = (uint8) (bitcount & 0xFF);
                de_buf[7] = (uint8) ((bitcount >> 8) & 0xFF);
                de_buf[8] = (uint8) (icon_size & 0xFF);
                de_buf[9] = (uint8) ((icon_size >> 8) & 0xFF);
                de_buf[10] = (uint8) ((icon_size >> 16) & 0xFF);
                de_buf[11] = (uint8) ((icon_size >> 24) & 0xFF);
                de_buf[12] = (uint8) (running & 0xFF);
                de_buf[13] = (uint8) ((running >> 8) & 0xFF);
                de_buf[14] = (uint8) ((running >> 16) & 0xFF);
                de_buf[15] = (uint8) ((running >> 24) & 0xFF);
                dirents.append(de_buf);

                uint8[] img = d[(int) icon_foff : (int) (icon_foff + icon_size)];
                body.append(img);
                running += icon_size;
                real_count++;
            }

            if (real_count == 0) return null;

            var ico = new ByteArray();
            uint8 hdr[6];
            hdr[0] = 0; hdr[1] = 0;
            hdr[2] = 1; hdr[3] = 0;
            hdr[4] = (uint8) (real_count & 0xFF);
            hdr[5] = (uint8) ((real_count >> 8) & 0xFF);
            ico.append(hdr);
            ico.append(dirents.data);
            ico.append(body.data);

            if (real_count < count) {
                uint pad = (uint) (count - real_count) * 16;
                var padded = new ByteArray();
                padded.append(hdr);
                padded.append(dirents.data);
                uint8[] zeros = new uint8[pad];
                padded.append(zeros);
                padded.append(body.data);
                ico = padded;
            }

            var bytes = new GLib.Bytes(ico.data);
            var stream = new MemoryInputStream.from_bytes(bytes);
            return new Gdk.Pixbuf.from_stream(stream);
        }
    }

    public class ExeIconPlugin : Object, Singularity.FilesPlugin {
        private ExeIconProvider? provider = null;
        private Singularity.FilesPluginContext? ctx = null;

        public void activate(Singularity.FilesPluginContext context) {
            ctx = context;
            provider = new ExeIconProvider();
            context.add_file_icon_provider(provider);
        }

        public void deactivate() {
            if (ctx != null && provider != null) {
                ctx.remove_file_icon_provider(provider);
            }
            provider = null;
            ctx = null;
        }
    }
}

[ModuleInit]
public void peas_register_types(GLib.TypeModule module) {
    var objmodule = module as Peas.ObjectModule;
    objmodule.register_extension_type(
        typeof(Singularity.FilesPlugin),
        typeof(Singularity.ExeIcon.ExeIconPlugin));
}
