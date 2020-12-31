#include <openjpeg-2.3/openjpeg.h>
#include <stdio.h>

#include <vector>
#include <string>
#include <cstring>

// credits: https://blog.csdn.net/10km/article/details/50607008

typedef unsigned char uint8_t;
typedef unsigned short uint16_t;
typedef unsigned int uint32_t;
#define DEFAULT_MEM_STREAM_INIT_SIZE (1024 * 16)

static void error_callback(const char *msg, void *client_data)
{
	fprintf(stderr, "[ERROR] %s", msg);
}

static void warning_callback(const char *msg, void *client_data)
{
	fprintf(stderr, "[WARNING] %s", msg);
}

static void info_callback(const char *msg, void *client_data)
{
#ifndef NDEBUG
	fprintf(stdout, "[INFO] %s", msg);
#endif
}

struct BmpFileHeader
{
	uint8_t bfType[2] = {'B', 'M'}; /* 'BM' for Bitmap (19776) */
	uint32_t bfSize = 0;			/* Size of the file        */
	uint16_t bfReserved1 = 0;		/* Reserved : 0            */
	uint16_t bfReserved2 = 0;		/* Reserved : 0            */
	uint32_t bfOffBits = 0;			/* Offset                  */
	uint32_t biSize = 40;			/* Size of the structure in bytes */
	uint32_t biWidth;				/* Width of the image in pixels */
	uint32_t biHeight;				/* Height of the image in pixels */
	uint16_t biPlanes = 1;			/* 1 */
	uint16_t biBitCount = 8;		/* Number of color bits by pixels */
	uint32_t biCompression = 0;		/* Type of encoding 0: none 1: RLE8 2: RLE4 */
	uint32_t biSizeImage = 0;		/* Size of the image in bytes */
	uint32_t biXpelsPerMeter = 0;	/* Horizontal (X) resolution in pixels/meter */
	uint32_t biYpelsPerMeter = 0;	/* Vertical (Y) resolution in pixels/meter */
	uint32_t biClrUsed = 0;			/* Number of color used in the image (0: ALL) */
	uint32_t biClrImportant = 0;	/* Number of important color (0: ALL) */
} __attribute__((packed));

static opj_image_t *bmpToImage(const uint8_t *bits, uint32_t length)
{
	const BmpFileHeader &bfh = *reinterpret_cast<const BmpFileHeader *>(bits);

	if (bfh.biBitCount != 24)
	{
		return nullptr;
	}

	int width = bfh.biWidth;
	int height = bfh.biHeight;
	int channels = 3;

	bits = bits + bfh.bfOffBits;

	opj_image_cmptparm_t cmptparm[4] = {0};
	for (int i = 0; i < 4; i++)
	{
		cmptparm[i].prec = 8;
		cmptparm[i].bpp = 8;
		cmptparm[i].sgnd = 0;
		cmptparm[i].dx = 1;
		cmptparm[i].dy = 1;
		cmptparm[i].w = (OPJ_UINT32)(width);
		cmptparm[i].h = (OPJ_UINT32)(height);
	}

	int stride = (width * channels + 3) / 4 * 4;

	opj_image_t *image = opj_image_create((OPJ_UINT32)(channels), cmptparm, OPJ_CLRSPC_SRGB);
	if (image == nullptr)
		return nullptr;

	image->x0 = 0;
	image->y0 = 0;
	image->x1 = image->x0 + width;
	image->y1 = image->y0 + height;

	int index = 0;
	for (int y = 0; y < height; ++y)
	{
		const uint8_t *line = static_cast<const uint8_t *>(bits) + stride * (height - 1 - y);
		for (int x = 0; x < width; ++x)
		{
			const uint8_t *pixel = line + channels * x;
			image->comps[0].data[index] = (OPJ_INT32)pixel[2];
			image->comps[1].data[index] = (OPJ_INT32)pixel[1];
			image->comps[2].data[index] = (OPJ_INT32)pixel[0];
			++index;
		}
	}

	return image;
}

static int imageToBmp(opj_image_t *image, void **data, uint32_t *outlen)
{
	int channels = image->numcomps;
	if (channels != 3)
		return -1;

	int width = image->comps[0].w;
	int height = image->comps[0].h;
	int stride = (width * channels + 3) / 4 * 4;
	int total_size = stride * height + sizeof(BmpFileHeader);

	uint8_t *bits = (uint8_t *)malloc(total_size);
	*data = bits;
	*outlen = total_size;

	BmpFileHeader *bfh = (BmpFileHeader *)(bits);
	(*bfh) = BmpFileHeader{};
	bfh->bfSize = total_size;
	bfh->bfOffBits = sizeof(BmpFileHeader);
	bfh->biWidth = width;
	bfh->biHeight = height;
	bfh->biBitCount = 24;

	int index = 0;
	bits += sizeof(BmpFileHeader);
	for (int y = 0; y < height; ++y)
	{
		uint8_t *line = bits + stride * (height - 1 - y);
		for (int x = 0; x < width; ++x)
		{
			uint8_t *pixel = line + channels * x;
			pixel[0] = (uint8_t)(image->comps[2].data[index]);
			pixel[1] = (uint8_t)(image->comps[1].data[index]);
			pixel[2] = (uint8_t)(image->comps[0].data[index]);
			++index;
		}
	}

	return 0;
}

// mem_stream interface
struct mem_stream
{
protected:
	uint8_t *start_ = nullptr;
	uint8_t *last_ = nullptr;
	uint8_t *cursor_ = nullptr;
	uint8_t *end_ = nullptr;

public:
	virtual OPJ_SIZE_T read(void *buffer, OPJ_SIZE_T nbytes) { return 0; }
	virtual OPJ_SIZE_T write(void *buffer, OPJ_SIZE_T nbytes) { return 0; }
	virtual OPJ_BOOL seek(OPJ_OFF_T nbytes)
	{
		if (nbytes >= 0)
		{
			cursor_ = start_ + nbytes;
			return OPJ_TRUE;
		}

		return OPJ_FALSE;
	}

	virtual OPJ_OFF_T skip(OPJ_OFF_T nbytes)
	{
		auto nc = cursor_ + nbytes;
		if (nc >= start_)
		{
			cursor_ = nc;
			return nbytes;
		}

		return (OPJ_OFF_T)-1;
	}

	virtual OPJ_UINT64 length() const
	{
		return (OPJ_UINT64)(last_ - start_);
	}

	virtual uint8_t *dataptr() const = 0;
	virtual void close() {}
	virtual OPJ_BOOL is_read_stream() const = 0;
	virtual ~mem_stream() {}
};

static void mem_stream_close(mem_stream *s)
{
	s->close();
}

static OPJ_BOOL mem_stream_seek(OPJ_OFF_T nbytes, mem_stream *s)
{
	return s->seek(nbytes);
}

static OPJ_OFF_T mem_stream_skip(OPJ_OFF_T nbytes, mem_stream *s)
{
	return s->skip(nbytes);
}

static OPJ_SIZE_T mem_stream_write(void *buffer, OPJ_SIZE_T nbytes, mem_stream *s)
{
	return s->write(buffer, nbytes);
}

static OPJ_SIZE_T mem_stream_read(void *buffer, OPJ_SIZE_T nbytes, mem_stream *s)
{
	return s->read(buffer, nbytes);
}

class mem_write_stream : public mem_stream
{
	std::vector<uint8_t> data_;

public:
	mem_write_stream(size_t init_capacity = DEFAULT_MEM_STREAM_INIT_SIZE) : data_(init_capacity)
	{
		start_ = dataptr();
		end_ = start_ + data_.size();
		cursor_ = start_;
		last_ = start_;
	}

	virtual OPJ_SIZE_T write(void *buffer, OPJ_SIZE_T nbytes)
	{
		if (cursor_ + nbytes > end_)
		{
			auto off_cur = cursor_ - start_;
			auto off_last = last_ - start_;
			data_.resize(data_.size() + std::max((OPJ_SIZE_T)(nbytes + cursor_ - end_), (OPJ_SIZE_T)data_.size())); //at least doubling the size

			start_ = dataptr();
			end_ = start_ + data_.size();
			last_ = start_ + off_last;
			cursor_ = start_ + off_cur;
		}
		memcpy(cursor_, buffer, nbytes);
		auto old_cursor = cursor_;
		cursor_ += nbytes;
		if (cursor_ > last_)
		{
			if (old_cursor > last_)
				memset(last_, 0, old_cursor - last_);
			last_ = cursor_;
		}
		return nbytes;
	}

	virtual OPJ_SIZE_T read(void *buffer, OPJ_SIZE_T nbytes) const { return 0; }
	virtual uint8_t *dataptr() const { return const_cast<uint8_t *>(data_.data()); }
	virtual OPJ_BOOL is_read_stream() const { return 0; }
};

class mem_read_stream : public mem_stream
{
	const uint8_t *data_ = nullptr;
	size_t size_ = 0;

public:
	mem_read_stream(const void *data, size_t size) : data_(reinterpret_cast<const uint8_t *>(data)), size_(size)
	{
		start_ = const_cast<uint8_t *>(data_);
		cursor_ = start_;
		end_ = last_ = start_ + size;
	}

	virtual OPJ_SIZE_T read(void *buffer, OPJ_SIZE_T nbytes)
	{
		if (last_ > cursor_)
		{
			auto len = std::min((OPJ_SIZE_T)(last_ - cursor_), nbytes);
			if (len)
			{
				memcpy(buffer, cursor_, len);
				cursor_ += len;
				return len;
			}
		}
		return (OPJ_SIZE_T)-1;
	}

	virtual uint8_t *dataptr() const { return const_cast<uint8_t *>(data_); }
	virtual OPJ_BOOL is_read_stream() const { return 1; }
};

static opj_stream_t *create_stream(mem_stream &mstream, OPJ_SIZE_T size)
{
	opj_stream_t *stream = opj_stream_create(size, mstream.is_read_stream());
	if (stream == nullptr)
		return nullptr;

	opj_stream_set_user_data(stream, std::addressof(mstream), opj_stream_free_user_data_fn(mem_stream_close));
	opj_stream_set_user_data_length(stream, mstream.length());
	opj_stream_set_read_function(stream, opj_stream_read_fn(mem_stream_read));
	opj_stream_set_write_function(stream, opj_stream_write_fn(mem_stream_write));
	opj_stream_set_skip_function(stream, opj_stream_skip_fn(mem_stream_skip));
	opj_stream_set_seek_function(stream, opj_stream_seek_fn(mem_stream_seek));

	return stream;
}

extern "C" int jp2EncodeImage(const uint8_t *bits, uint32_t size, void **data, uint32_t *outlen, OPJ_CODEC_FORMAT format, uint32_t quality)
{
	int ret = -1;

	opj_image_t *image = bmpToImage(bits, size);
	if (image == nullptr)
	{
		return -1;
	}

	opj_cparameters_t parameters = {0};
	opj_set_default_encoder_parameters(&parameters);

	parameters.tcp_numlayers = 1;
	parameters.tcp_distoratio[0] = (float)(quality > 100 ? 100 : quality);
	parameters.cp_fixed_quality = 1;
	//	parameters.tcp_rates[0] = 10;
	parameters.cp_disto_alloc = 1;
	parameters.tcp_mct = 1;
	parameters.cod_format = format;
	parameters.irreversible = 1;

	std::string comment;
	if (parameters.cp_comment == nullptr)
	{
		comment = "openjpeg/";
		comment += opj_version();
		parameters.cp_comment = (char *)comment.c_str();
	}

	opj_codec_t *codec = opj_create_compress((CODEC_FORMAT)parameters.cod_format);

	opj_set_info_handler(codec, info_callback, 0);
	opj_set_warning_handler(codec, warning_callback, 0);
	opj_set_error_handler(codec, error_callback, 0);
	opj_setup_encoder(codec, &parameters, image);

	mem_write_stream out;
	opj_stream_t *stream = create_stream(out, OPJ_J2K_STREAM_CHUNK_SIZE);

	if (!opj_start_compress(codec, image, stream))
	{
		ret = -3;
		goto err_exit;
	}

	if (!opj_encode(codec, stream))
	{
		ret = -4;
		goto err_exit;
	}

	if (!opj_end_compress(codec, stream))
	{
		ret = -5;
		goto err_exit;
	}

	*outlen = uint32_t(out.length());
	*data = malloc(*outlen);
	memcpy(*data, out.dataptr(), *outlen);
	ret = 0;

err_exit:
	if (image != nullptr)
		opj_image_destroy(image);
	if (stream != nullptr)
		opj_stream_destroy(stream);
	if (codec != nullptr)
		opj_destroy_codec(codec);

	return ret;
}

extern "C" int jp2DecodeImage(const void *bits, uint32_t length, void **data, uint32_t *outlen, OPJ_CODEC_FORMAT format)
{
	if (format != OPJ_CODEC_J2K && format != OPJ_CODEC_JP2 && format != OPJ_CODEC_JPT)
		return -1;

	int ret = -1;

	opj_dparameters_t parameters;
	opj_set_default_decoder_parameters(&parameters);
	parameters.decod_format = format;

	opj_image_t *image = nullptr;
	opj_codec_t *codec = opj_create_decompress((OPJ_CODEC_FORMAT)parameters.decod_format);

	mem_read_stream in(bits, length);
	opj_stream_t *stream = create_stream(in, OPJ_J2K_STREAM_CHUNK_SIZE);

	opj_set_info_handler(codec, info_callback, 0);
	opj_set_warning_handler(codec, warning_callback, 0);
	opj_set_error_handler(codec, error_callback, 0);

	if (!opj_setup_decoder(codec, &parameters))
	{
		ret = -2;
		goto err_exit;
	}

	if (!opj_read_header(stream, codec, &image))
	{
		ret = -3;
		goto err_exit;
	}

	// decode full image
	if (!parameters.nb_tile_to_decode)
	{

		if (!opj_set_decode_area(codec, image, (OPJ_INT32)(parameters.DA_x0), (OPJ_INT32)(parameters.DA_y0),
								 (OPJ_INT32)(parameters.DA_x1), (OPJ_INT32)(parameters.DA_y1)))
		{
			ret = -4;
			goto err_exit;
		}

		if (!(opj_decode(codec, stream, image) && opj_end_decompress(codec, stream)))
		{
			ret = -5;
			goto err_exit;
		}
	}
	else
	{
		if (!opj_get_decoded_tile(codec, stream, image, parameters.tile_index))
		{
			ret = -6;
			goto err_exit;
		}
	}

	if (imageToBmp(image, data, outlen) < 0)
	{
		ret = -7;
		goto err_exit;
	}

	ret = 0;

err_exit:
	if (image != nullptr)
		opj_image_destroy(image);
	if (stream != nullptr)
		opj_stream_destroy(stream);
	if (codec != nullptr)
		opj_destroy_codec(codec);

	return ret;
}

#if defined(MAIN)
#include <fstream>

int main(int argc, const char *argv[])
{
	if (argc != 4)
	{
		printf("Usage: %s encode|decode <infile> <outfile>\n", argv[0]);
		return -1;
	}

	std::ifstream file(argv[2], std::ios::binary | std::ios::ate);
	std::streamsize size = file.tellg();
	file.seekg(0, std::ios::beg);

	std::vector<uint8_t> buf(size);
	if (!file.read((char *)buf.data(), size))
	{
		return -1;
	}

	std::string op = argv[1];
	void *out = nullptr;
	uint32_t outlen = 0;
	if (op == "encode")
	{
		int ret = jp2EncodeImage(buf.data(), buf.size(), &out, &outlen, OPJ_CODEC_JP2, 90);
		if (ret < 0)
		{
			printf("Failed to encode %s: %d\n", argv[2], ret);
			return ret;
		}
	}
	else
	{
		int ret = jp2DecodeImage(buf.data(), buf.size(), &out, &outlen, OPJ_CODEC_JP2);
		if (ret < 0)
		{
			printf("Failed to decode %s: %d\n", argv[2], ret);
			return ret;
		}
	}

	std::ofstream outfile(argv[3], std::ios::binary | std::ios::out);
	if (!outfile.write((const char *)out, outlen))
	{
		return -2;
	}

	jp2FreeBuffer(out);
	return 0;
}

#endif
