
from tkinter import *
from tkinter import filedialog, messagebox, simpledialog
from PIL import Image

def xor_encrypt_decrypt(message, key):
    return ''.join(chr(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(message))

def to_binary(data):
    return ''.join(format(ord(char), '08b') for char in data)

def to_text(binary_data):
    chars = [binary_data[i:i+8] for i in range(0, len(binary_data), 8)]
    return ''.join(chr(int(b, 2)) for b in chars)

def encode():
    image_path = filedialog.askopenfilename()
    if not image_path:
        return

    img = Image.open(image_path)
    encoded = img.copy()
    width, height = img.size

    message = simpledialog.askstring("Input", "Enter the message:")
    if not message:
        return

    key = simpledialog.askstring("Password", "Enter a password:", show='*')
    if not key:
        return

    encrypted_msg = xor_encrypt_decrypt(message + "#####", key)
    binary_msg = to_binary(encrypted_msg)

    if len(binary_msg) > width * height * 3:
        messagebox.showerror("Error", "Message is too long for this image.")
        return

    data_index = 0
    for y in range(height):
        for x in range(width):
            pixel = list(img.getpixel((x, y)))
            for i in range(3):  # R, G, B
                if data_index < len(binary_msg):
                    pixel[i] = pixel[i] & ~1 | int(binary_msg[data_index])
                    data_index += 1
            encoded.putpixel((x, y), tuple(pixel))
            if data_index >= len(binary_msg):
                break
        if data_index >= len(binary_msg):
            break

    save_path = filedialog.asksaveasfilename(defaultextension=".png", filetypes=[("PNG files", "*.png")])
    if save_path:
        encoded.save(save_path)
        messagebox.showinfo("Success", "Message encoded and image saved.")


# --- GUI setup ---

root = Tk()
root.title("Image Steganography")
root.configure(bg="#aec6cf")  # background color

frame = Frame(root, bg="#aec6cf")
frame.pack(padx=40, pady=80)
app_title = Label(frame, text="StegoMagic",
                  font=("Bauhaus 93", 18),
                  fg="#003366", bg="#aec6cf")
app_title.pack(side="top", anchor="w",pady=(0, 10))


# Instruction label
instruction = Label(frame, text="Please upload an image to hide your secret message.",
                    bg="#aec6cf", fg="#333333", font=("Arial", 12, "bold"))
instruction.pack(pady=(0, 15))

# Encode button
encode_button = Button(frame, text="Encode Message", command=encode,
                       bg="#4CAF50", fg="white", font=("Arial", 12, "bold"), padx=10, pady=5)
encode_button.pack(pady=5)

root.mainloop()