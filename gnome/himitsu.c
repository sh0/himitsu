//
// Himitsu
// by sh0
//

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/sha.h>
#include <glib.h>
#include <gnome-keyring.h>
#include <gtk/gtk.h>

static void pwhash_dump(char* name, unsigned char* data, unsigned int size)
{
    printf("%s = ", name);
    unsigned int i;
    for (i=0; i<size; i++)
        printf("%02x", data[i]);
    printf("\n");
}

static void pwhash_mix(unsigned char* hash_target, unsigned char* hash_master)
{
    // Mix
    unsigned char hash_mix[SHA_DIGEST_LENGTH];
    int i;
    for (i=0; i<SHA_DIGEST_LENGTH; i++)
        hash_mix[i] = hash_target[i] ^ hash_master[i];
    //pwhash_dump("xor", hash_mix, sizeof(hash_mix));

    // Rehash
    unsigned char hash_final[SHA_DIGEST_LENGTH];
    SHA1(hash_mix, sizeof(hash_mix), hash_final);
    //pwhash_dump("sha1(xor)", hash_final, sizeof(hash_final));

    // Base64
    char b64_text[(SHA_DIGEST_LENGTH + 2) / 3 * 4 + 1];
    int b64_size = 0;
    int j;
    for (i=0; i<SHA_DIGEST_LENGTH - 2; i += 3) {
        unsigned int v = (hash_final[i + 2] << 16) | (hash_final[i + 1] << 8) | (hash_final[i]);
        for (j=0; j<4; j++) {
            unsigned int f = (v & 0x3f);
            v = v >> 6;
            static const char base64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz012345678901=";
            b64_text[b64_size++] = base64[f];
        }
    }
    b64_text[b64_size] = '\0';
    if (strlen(b64_text) > 12)
        b64_text[12] = '\0';
    
    // Clipboard
    gtk_clipboard_set_text(gtk_clipboard_get(GDK_SELECTION_CLIPBOARD), b64_text, -1);
    gtk_clipboard_store(gtk_clipboard_get(GDK_SELECTION_CLIPBOARD));
    
    // Print
    //printf("hash: %s\n", b64_text);
    
    // Zero memory
    memset(b64_text, 0, sizeof(b64_text));
    memset(hash_mix, 0, sizeof(hash_mix));
    memset(hash_final, 0, sizeof(hash_final));
}

int main(int argc, char* argv[])
{
    // GTK
    gtk_init(&argc, &argv);
    
    // Check for target
    if (argc < 2) {
        printf("usage: himitsu target\n");
        return 1;
    }
    
    // Schema
    GnomeKeyringPasswordSchema kr_schema = {
        GNOME_KEYRING_ITEM_GENERIC_SECRET,
        {
            { "himitsu", GNOME_KEYRING_ATTRIBUTE_TYPE_STRING },
            { NULL, 0 }
        }
    };
    
    // Master password reset
    int reset_flag = FALSE;
    if (strcmp(argv[1], "reset") == 0) {
        // Read from console
        gchar* kr_pass = getpass("enter master password: ");
        
        // Store
        GnomeKeyringResult kr_ret = gnome_keyring_store_password_sync(&kr_schema, GNOME_KEYRING_SESSION, "himitsu master password", kr_pass, "himitsu", "master", NULL);
        if (kr_ret != GNOME_KEYRING_RESULT_OK) {
            printf("unable to store master password! error=%s\n", gnome_keyring_result_to_message(kr_ret));
        }
        
        // Quit
        return 0;
    }

    // Hash target
    unsigned char hash_target[SHA_DIGEST_LENGTH];
    SHA1(argv[1], strlen(argv[1]), hash_target);

    // Get master key
    gchar* kr_pass = NULL;
    GnomeKeyringResult kr_ret = gnome_keyring_find_password_sync(&kr_schema, &kr_pass, "himitsu", "master", NULL);
    if (kr_ret == GNOME_KEYRING_RESULT_NO_SUCH_KEYRING) {
        // Read from console
        kr_pass = getpass("enter master password: ");
        
        // Store
        kr_ret = gnome_keyring_store_password_sync(&kr_schema, GNOME_KEYRING_SESSION, "himitsu master password", kr_pass, "himitsu", "master", NULL);
        if (kr_ret != GNOME_KEYRING_RESULT_OK) {
            printf("unable to store master password! error=%s\n", gnome_keyring_result_to_message(kr_ret));
        }
    } else if (kr_ret != GNOME_KEYRING_RESULT_OK) {
        printf("gnome keyring failure! error=%s\n", gnome_keyring_result_to_message(kr_ret));
        return 1;
    }
    
    // Hash master
    unsigned char hash_master[SHA_DIGEST_LENGTH];
    SHA1(kr_pass, strlen(kr_pass), hash_master);
    
    // Mix and print result
    //pwhash_dump("sha1(target)", hash_target, sizeof(hash_target));
    //pwhash_dump("sha1(master)", hash_master, sizeof(hash_master));
    pwhash_mix(hash_target, hash_master);
    
    // Zero memory
    gnome_keyring_free_password(kr_pass);
    memset(hash_target, 0, SHA_DIGEST_LENGTH);
    memset(hash_master, 0, SHA_DIGEST_LENGTH);
    
    // Return
    return 0;
}

