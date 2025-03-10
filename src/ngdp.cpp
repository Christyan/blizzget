#include "ngdp.h"
#include "base/http.h"
#include "base/path.h"
#include "base/checksum.h"
#include <algorithm>

#pragma comment(lib, "Ws2_32.lib")

namespace NGDP {

  const std::string HOST = "http://m.wowlibrary.com/"; // "http://us.patch.battle.net:1119";

  const std::map<std::string, std::string> ProgramCodes = {
    //{ "agent", "Battle.net Agent" },
    //{ "bna", "Battle.net App" },
    //{ "bnt", "Heroes of the Storm Alpha (Deprecated)" },
    //{ "d3", "Diablo 3 Retail" },
    //{ "d3cn", "Diablo 3 China" },
    //{ "d3t", "Diablo 3 Test" },
    //{ "demo", "Demo (Partial)" },
    //{ "dst2a", "Destiny 2 Alpha (Encrypted)" },
    //{ "hero", "Heroes of the Storm Retail" },
    //{ "herot", "Heroes of the Storm Test" },
    //{ "heroc", "Heroes of the Storm Tournament" },
    //{ "hsb", "Hearthstone" },
    //{ "hst", "Hearthstone Test (Partial)" },
    //{ "osib", "Diablo II: Resurrected (Alpha)" },
    //{ "pro", "Overwatch Retail" },
    //{ "prot", "Overwatch Test" },
    //{ "prob", "Overwatch Beta" },
    //{ "proc", "Overwatch Tournament" },
    //{ "prodev", "Overwatch Dev (Encrypted)" },
    //{ "s1", "StarCraft I" },
    //{ "s1a", "StarCraft I Alpha (Encrypted)" },
    //{ "s1t", "StarCraft I Test" },
    //{ "sc2", "StarCraft II (Deprecated)" },
    //{ "s2", "StarCraft II Retail" },
    //{ "s2t", "StarCraft II Test (Deprecated)" },
    //{ "s2b", "StarCraft II Beta (Deprecated)" },
    //{ "test", "Test (Deprecated)" },
    //{ "storm", "Heroes of the Storm (Deprecated)" },
    //{ "war3", "Warcraft III Old Ver (Partial)" },
    //{ "w3", "Warcraft III" },
    { "wow", "World of Warcraft Retail" },
    //{ "wowt", "World of Warcraft Test" },
    //{ "wow_beta", "World of Warcraft Beta" },
    //{ "wow_classic", "World of Warcraft Classic" },
    //{ "wow_classic_beta", "World of Warcraft Classic Beta" },
    //{ "wowdemo", "World of Warcraft Demo" },
    //{ "wowdev", "World of Warcraft Dev" },
  };

  NGDP::NGDP(std::string const& app)
    : program_(app)
  {
    //File file = HttpRequest::get(HOST + "/" + app + "/cdns");
    File file = HttpRequest::get("http://26972.wtfthis.eu/26972/cdn");
    if (!file) {
      throw Exception("failed to fetch cdns file");
    }
    for (std::string const& line : file) {
      if (line.substr(0, 2) == "##") continue;
      if (line.find('!') != std::string::npos || line.empty()) continue;
      auto parts = split(line, '|');
      auto& config = cdns_[parts[0]];
      config.path = parts[1];
      config.hosts = split(parts[2], ' ');
    }

    file = HttpRequest::get("http://26972.wtfthis.eu/26972/versions");
    if (!file) {
      throw Exception("failed to fetch versions file");
    }
    for (std::string const& line : file) {
      if (line.substr(0, 2) == "##") continue;
      if (line.find('!') != std::string::npos || line.empty()) continue;
      auto parts = split(line, '|');
      auto& config = versions_[parts[0]];
      config.build = parts[1];
      config.cdn = parts[2];
      config.id = std::stoi(parts[4]);
      config.version = parts[5];
      if (cdns_.count(parts[0])) {
        regions_.push_back(parts[0]);
      }
    }
  }

  bool NGDP::setRegion(std::string const& region) {
    if (!cdns_.count(region) || !versions_.count(region)) {
      return false;
    }
    region_ = region;
    base_ = "http://" + cdns_[region].hosts[0] + "/" + cdns_[region].path + "/";
    return true;
  }

  std::string NGDP::geturl(std::string const& hash, std::string const& type, bool index) const {
    std::string url = base_ + type + "/" + hash.substr(0, 2) + "/" + hash.substr(2, 2) + "/" + hash;
    if (index) url += ".index";
    return url;
  }
  File NGDP::load(std::string const& hash, std::string const& type, bool index) const {
    return HttpRequest::get(geturl(hash, type, index));
  }

  File DecodeBLTE(File& blte, uint32 eusize) {
    if (blte.read32(true) != 'BLTE') return File();
    uint32 headerSize = blte.read32(true);
    if (headerSize) {
      std::vector<uint32> csize;
      std::vector<uint32> usize;
      uint16 flags = blte.read16(true);
      uint16 chunks = blte.read16(true);
      for (uint16 i = 0; i < chunks; ++i) {
        csize.push_back(blte.read32(true));
        usize.push_back(blte.read32(true));
        blte.seek(16, SEEK_CUR);
      }
      MemoryFile dst;
      std::vector<uint8> tmp;
      for (uint16 i = 0; i < chunks; ++i) {
        uint8 type = blte.read8();
        if (type == 'N') {
          if (csize[i] - 1 != usize[i]) return File();
          blte.read(dst.reserve(usize[i]), usize[i]);
        } else if (type == 'Z') {
          tmp.resize(csize[i] - 1);
          blte.read(&tmp[0], tmp.size());
          if (gzinflate(&tmp[0], tmp.size(), dst.reserve(usize[i]), &usize[i])) return File();
        } else {
          // unsupported compression
          return File();
        }
      }
      dst.seek(0);
      return dst;
    } else {
      uint64 offset = blte.tell();
      uint64 size = blte.size() - offset;
      if (blte.read8() == 'N') {
        return blte.subfile(offset, size);
      } else if (eusize) {
        blte.seek(offset, SEEK_SET);
        std::vector<uint8> tmp(size);
        blte.read(&tmp[0], size);
        MemoryFile dst;
        if (gzinflate(&tmp[0], size, dst.reserve(eusize), &eusize)) return File();
        dst.seek(0);
        return dst;
      } else {
        // unsupported compression
        return File();
      }
    }
  }

  ConfigFile ParseConfig(File& file) {
    ConfigFile result;
    if (!file) return result;
    for (std::string const& line : file) {
      if (line[0] == '#') continue;
      size_t pos = line.find(" = ");
      if (pos == std::string::npos) continue;
      result[line.substr(0, pos)] = line.substr(pos + 3);
    }
    return result;
  }

#pragma pack(push, 1)
  struct EncodingFileHeader {
    uint16 signature;
    uint8 unk;
    uint8 sizeA;
    uint8 sizeB;
    uint16 flagsA;
    uint16 flagsB;
    uint32 entriesA;
    uint32 entriesB;
    uint8 unk2;
    uint32 stringSize;
  };
  struct DataFileHeader
  {
      uint8 bltehash[0x10];
      uint32 size = 0;
      uint16 flags = 0;
      uint32 checksumA = 0;
      uint32 checksumB = 0;
  };
#pragma pack(pop)

  void from_string(Hash hash, std::string const& str) {
    int val;
    for (int i = 0; i < sizeof(Hash); ++i) {
      sscanf(&str[i * 2], "%02x", &val);
      hash[i] = val;
    }
  }
  std::string to_string(const Hash hash) {
    return MD5::format(hash);
  }

  Encoding::Encoding(File& file) {
    EncodingFileHeader header;
    file.read(&header, sizeof header);
    flip(header.signature);
    flip(header.entriesA);
    flip(header.entriesB);
    flip(header.stringSize);
    if (header.signature != 'EN' || header.sizeA != 16 || header.sizeB != 16) {
      throw Exception("invalid encoding file");
    }

    uint32 size = file.size();
    uint32 posHeaderA = sizeof(EncodingFileHeader) + header.stringSize;
    uint32 posEntriesA = posHeaderA + header.entriesA * 32;
    uint32 posHeaderB = posEntriesA + header.entriesA * 4096;
    uint32 posEntriesB = posHeaderB + header.entriesB * 32;
    uint32 posLayout = posEntriesB + header.entriesB * 4096;

    data_.resize(header.stringSize + (header.entriesA + header.entriesB) * 4096 + (size - posLayout));
    char* layouts = (char*) &data_[0];
    uint8* entriesA = &data_[header.stringSize];
    uint8* entriesB = entriesA + header.entriesA * 4096;
    layout_ = (char*) (entriesB + header.entriesB * 4096);

    file.read(layouts, header.stringSize);
    file.seek(posEntriesA, SEEK_SET);
    file.read(entriesA, header.entriesA * 4096);
    file.seek(posEntriesB, SEEK_SET);
    file.read(entriesB, header.entriesB * 4096);
    file.read(layout_, size - posLayout);

    for (char* ptr = layouts; ptr < layouts + header.stringSize; ++ptr) {
      layouts_.push_back(ptr);
      while (*ptr) ++ptr;
    }

    file.seek(posHeaderA, SEEK_SET);
    encodingTable_.resize(header.entriesA);
    for (uint32 i = 0; i < header.entriesA; ++i) {
      file.read(encodingTable_[i].hash, sizeof(Hash));
      Hash blockHash, realHash;
      file.read(blockHash, sizeof blockHash);
      MD5::checksum(entriesA, 4096, realHash);
      if (memcmp(realHash, blockHash, sizeof(Hash))) {
        throw Exception("encoding file checksum mismatch");
      }
      for (uint8* ptr = entriesA; ptr + sizeof(EncodingEntry) <= entriesA + 4096;) {
        EncodingEntry* entry = reinterpret_cast<EncodingEntry*>(ptr);
        if (!entry->keyCount) break;
        encodingTable_[i].entries.push_back(entry);
        flip(entry->usize);
        ptr += sizeof(EncodingEntry) + (entry->keyCount - 1) * sizeof(Hash);
      }
      entriesA += 4096;
    }

    Hash nilHash;
    memset(nilHash, 0, sizeof(Hash));

    file.seek(posHeaderB, SEEK_SET);
    layoutTable_.resize(header.entriesB);
    for (uint32 i = 0; i < header.entriesB; ++i) {
      file.read(layoutTable_[i].key, sizeof(Hash));
      Hash blockHash, realHash;
      file.read(blockHash, sizeof blockHash);
      MD5::checksum(entriesB, 4096, realHash);
      if (memcmp(realHash, blockHash, sizeof(Hash))) {
        throw Exception("encoding file checksum mismatch");
      }
      for (uint8* ptr = entriesB; ptr + sizeof(LayoutEntry) <= entriesB + 4096;) {
        LayoutEntry* entry = reinterpret_cast<LayoutEntry*>(ptr);
        if (!memcmp(entry->key, nilHash, sizeof(Hash))) {
          break;
        }
        layoutTable_[i].entries.push_back(entry);
        flip(entry->stringIndex);
        flip(entry->csize);
        ptr += sizeof(LayoutEntry);
      }
      entriesB += 4096;
    }
  }

  template<class Vec, class Comp>
  typename Vec::const_iterator find_hash(Vec const& vec, Comp less) {
    if (vec.empty() || less(vec[0])) return vec.end();
    size_t left = 0, right = vec.size();
    while (right - left > 1) {
      size_t mid = (left + right) / 2;
      if (less(vec[mid])) {
        right = mid;
      } else {
        left = mid;
      }
    }
    return vec.begin() + left;
  }

  Encoding::EncodingEntry const* Encoding::getEncoding(const Hash hash) const {
    auto it = find_hash(encodingTable_, [&hash](EncodingHeader const& rhs) {
      return memcmp(hash, rhs.hash, sizeof(Hash)) < 0;
    });
    if (it == encodingTable_.end()) return nullptr;
    auto sub = find_hash(it->entries, [&hash](EncodingEntry const* rhs) {
      return memcmp(hash, rhs->hash, sizeof(Hash)) < 0;
    });
    if (sub == it->entries.end()) return nullptr;
    if (memcmp((*sub)->hash, hash, sizeof(Hash))) return nullptr;
    return *sub;
  }
  Encoding::LayoutEntry const* Encoding::getLayout(const Hash key) const {
    auto it = find_hash(layoutTable_, [&key](LayoutHeader const& rhs) {
      return memcmp(key, rhs.key, sizeof(Hash)) < 0;
    });
    if (it == layoutTable_.end()) return nullptr;
    auto sub = find_hash(it->entries, [&key](LayoutEntry const* rhs) {
      return memcmp(key, rhs->key, sizeof(Hash)) < 0;
    });
    if (sub == it->entries.end()) return nullptr;
    if (memcmp((*sub)->key, key, sizeof(Hash))) return nullptr;
    return *sub;
  }

  CascStorage::CascStorage(std::string const& root)
    : root_(root)
  {
    path::create(root / "config");
    path::create(root / "data");
    path::create(root / "indices");
    //path::create(root / "patch");

    std::vector<std::string> names;
    WIN32_FIND_DATA fdata;
    HANDLE hFind = FindFirstFile((root / "data" / "*").c_str(), &fdata);
    if (hFind == INVALID_HANDLE_VALUE) return;
    do {
      if (!(fdata.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
        names.push_back(fdata.cFileName);
      }
    } while (FindNextFile(hFind, &fdata));
    FindClose(hFind);

    for (std::string const& name : names) {
      DeleteFile((root / "data" / name).c_str());
    }
  }

  File& CascStorage::addConfig(std::string const& hash, File& file) {
    file.seek(0);
    File(root_ / "config" / hash.substr(0, 2) / hash.substr(2, 2) / hash, File::REWRITE).copy(file);
    file.seek(0);
    return file;
  }
  File& CascStorage::addIndex(std::string const& hash, File& file) {
    file.seek(0);
    File(root_ / "indices" / hash + ".index", File::REWRITE).copy(file);
    file.seek(0);
    return file;
  }
  File CascStorage::addData(std::string const& name) {
    return File(root_ / "data" / name, File::REWRITE);
  }

  File& CascStorage::addCache(std::string const& name, File& file) {
    file.seek(0);
    File(path::root() / "cache" / name, File::REWRITE).copy(file);
    file.seek(0);
    return file;
  }
  File CascStorage::addCache(std::string const& name) {
    return File(path::root() / "cache" / name, File::MODIFY);
  }
  File CascStorage::getCache(std::string const& name) {
    return File(path::root() / "cache" / name);
  }

  DataStorage::DataStorage(CascStorage& storage)
    : storage_(storage)
    , dataCount_(0)
  {
      index_.resize(16);
  }

  File& DataStorage::addFile(const Hash hash, File& file) {
    if (!file) return file;

    if (!data_ || (data_.size() + file.size() + 30) > MaxDataSize) {
        data_ = storage_.addData(fmtstring("data.%03u", dataCount_++));
        Hash sortedReconstructionHash[16];

        for (int i = 0; i < 16; ++i) {
            Hash reConstructionHeaderHash;
            memset(reConstructionHeaderHash, 0, sizeof reConstructionHeaderHash);

            char buf[256];
            memset(buf, 0, 256);
            gethostname(buf, 256);
            const std::string constStr = "data/data";
            MD5 md5;
            md5.process(buf, strlen(buf));
            md5.process(constStr.data(), constStr.length());
            md5.finish(reConstructionHeaderHash);
            memset(&reConstructionHeaderHash[9], 0, 7);

            reConstructionHeaderHash[0] = (uint8_t)i;
            reConstructionHeaderHash[1] = (uint8_t)(dataCount_ - 1);

            uint8 bucketIndex2 = cascGetBucketIndexCrossReference(reConstructionHeaderHash);
            memcpy(&sortedReconstructionHash[bucketIndex2][0], &reConstructionHeaderHash, sizeof reConstructionHeaderHash);
        }

        for (int i = 0; i < 16; ++i) {
            addIndex(i, sortedReconstructionHash[i], 0);
            addDataHeader(sortedReconstructionHash[i], 0, 1);
        }
    }

    uint8 bucketIndex = cascGetBucketIndex(hash);

    addIndex(bucketIndex, hash, file.size());
    addDataHeader(hash, file.size());

    file.seek(0);
    data_.copy(file);
    file.seek(0);
    return file;
  }

  void DataStorage::addIndex(uint8_t bucketIndex, const Hash hash, uint32 size)
  {
      index_[bucketIndex].emplace_back();
      auto& entry = index_[bucketIndex].back();
      memcpy(entry.hash, hash, sizeof(Hash));
      entry.index = dataCount_ - 1;
      entry.offset = data_.tell();
      entry.size = sizeof DataFileHeader + size;
  }

  void DataStorage::addDataHeader(const Hash hash, uint32 size, uint16 flags /*= 0*/)
  {
      DataFileHeader header;
      header.size = sizeof DataFileHeader + size;
      header.flags = flags;
      for (int i = 15; i >= 0; --i) {
          header.bltehash[15 - i] = hash[i];
      }

      header.checksumA = hashlittle(&header, 0x16, 0x3D6BE971);
      header.checksumB = checksum(&header, dataCount_ - 1, data_.tell());
      data_.write(&header, sizeof(header));
  }

#pragma pack(push, 1)
  struct IndexHeader {
    uint16 version = 7;
    uint8 keyIndex;
    uint8 extraBytes = 0;
    uint8 sizeBytes = 4;
    uint8 offsBytes = 5;
    uint8 keyBytes = 9;
    uint8 segmentBits = 30;
    uint64 maxOffset;
  };
  struct WriteIndexEntry {
    uint8 hash[9];
    uint8 pos[5];
    uint32 size;
  };
#pragma pack(pop)

  void DataStorage::writeIndex(size_t indexFileSize, int idx) {
    if (index_.empty()) return;
    if (index_.size() <= idx) return;
    if (index_[idx].empty()) return;

    uint32_t indexCounter = 0;

    {
        ++indexCounter;
        File index = storage_.addData(fmtstring("%02x%08x.idx", idx, indexCounter));

        IndexHeader header;
        header.keyIndex = idx;
        header.maxOffset = _byteswap_uint64(MaxDataSize);

        index.write32(sizeof(IndexHeader));
        index.write32(hashlittle(&header, sizeof header, 0));
        index.write(&header, sizeof header);
        // 8byte padding (32 byte block)
        index.write32(0);
        index.write32(0);
        

        std::sort(index_[idx].begin(), index_[idx].end(), [](IndexEntry const& lhs, IndexEntry const& rhs) {
            return memcmp(lhs.hash, rhs.hash, sizeof(Hash)) < 0;
            });


        uint32 blockPos = index.tell();
        uint32 blockSize = 0;
        uint32 blockHash = 0;
        uint32 secondBlockHash = 0;
        index.write32(blockSize);
        index.write32(blockHash);
        for (IndexEntry const& entry : index_[idx]) {
            WriteIndexEntry write;
            memcpy(write.hash, entry.hash, sizeof(write.hash));
            *(uint32*)(write.pos + 1) = _byteswap_ulong(entry.offset);
            write.pos[0] = entry.index / 4;
            write.pos[1] |= ((entry.index & 3) << 6);
            write.size = entry.size;

            index.write(&write, sizeof write);
            blockSize += sizeof(write);
            hashlittle2(&write, sizeof write, &blockHash, &secondBlockHash);
        }
        
        int32_t remainingAmount = indexFileSize - index.tell();

        std::vector<uint8_t> needRemainingData;
        needRemainingData.resize(remainingAmount); // need blocks end of file for client
        memset(needRemainingData.data(), 0, needRemainingData.size());
        index.write(needRemainingData.data(), needRemainingData.size());

        index.seek(blockPos, SEEK_SET);
        index.write32(blockSize);
        index.write32(blockHash);
    }
  }

}
