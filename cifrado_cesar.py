def cifrado_cesar(texto, corrimiento):
    resultado = ""
    for char in texto:
        # Si es letra mayúscula
        if char.isupper():
            resultado += chr((ord(char) - ord('A') + corrimiento) % 26 + ord('A'))
        # Si es letra minúscula
        elif char.islower():
            resultado += chr((ord(char) - ord('a') + corrimiento) % 26 + ord('a'))
        else:
            # Si no es letra, se mantiene igual
            resultado += char
    return resultado


# Programa principal
if __name__ == "__main__":
    texto = input("Ingrese el texto a cifrar: ")
    corrimiento = int(input("Ingrese el corrimiento (0-25): "))
    print("Texto cifrado:", cifrado_cesar(texto, corrimiento))
