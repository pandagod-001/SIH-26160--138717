import win32com.client
import os

def test_sapi():
    speaker = win32com.client.Dispatch("SAPI.SpVoice")
    os.makedirs("demo/final_video", exist_ok=True)
    out_file = os.path.abspath("demo/final_video/test_sapi_direct.wav")
    
    stream = win32com.client.Dispatch("SAPI.SpFileStream")
    # 3 = SSFMCreateForWrite
    stream.Open(out_file, 3, False)
    speaker.AudioOutputStream = stream
    
    text = "IPsecTrace is a protocol-aware system for analyzing encrypted IPsec network traffic without decrypting protected application payloads."
    speaker.Speak(text)
    stream.Close()
    
    print("Direct SAPI WAV generated:", os.path.exists(out_file), os.path.getsize(out_file), "bytes")

test_sapi()
