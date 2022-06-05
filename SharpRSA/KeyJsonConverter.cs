using System;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace SharpRSA
{
    public class KeyJsonConverter : JsonConverter<Key>
    {
        public override Key Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
        {
            throw new NotImplementedException();
        }

        public override void Write(Utf8JsonWriter writer, Key key, JsonSerializerOptions options)
        {
            writer.WriteStringValue(key.ToBase64());
        }
    }
}
