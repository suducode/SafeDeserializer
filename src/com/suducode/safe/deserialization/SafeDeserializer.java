package com.suducode.safe.deserialization;

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectStreamClass;
import java.util.List;

/**
 * This class helps with safely de serializing an object from a stream avoiding the known
 * vulnerability in native java de serialization.
 *
 * @param <T> De-serialized object will be cast to this type.
 * @author Sudharshan Krishnamurthy
 * @version 1.0
 */
public class SafeDeserializer<T> {

    private long length = 0;
    private long maxBytes = 0;
    private long maxObjects = 0;
    private InputStream inputStream;
    private List<Class<?>> safeClasses;

    /**
     * A de-serializer to replace the unsafe ObjectInputStream.readObject() method built into Java. This method
     * checks to be sure the classes referenced are safe, the number of objects is limited to something sane,
     * and the number of bytes is limited to a reasonable number. The returned Object is also cast to the
     * specified type.
     *
     * @param safeClasses List of Classes allowed in serialized object being read.
     * @param maxObjects  long representing the maximum number of objects allowed inside the serialized
     *                    object being read.
     * @param maxBytes    long representing the maximum number of bytes allowed to be read from the InputStream.
     * @param inputStream InputStream containing an untrusted serialized object.
     * @return Object read from the stream. (cast to the Class of the type parameter)
     * @throws IOException            might be thrown while reading fom the stream.
     * @throws ClassNotFoundException might be thrown while casting the deserialized object.
     */
    public SafeDeserializer(List<Class<?>> safeClasses, long maxObjects, long maxBytes, InputStream inputStream) {
        this.safeClasses = safeClasses;
        this.maxBytes = maxBytes;
        this.maxObjects = maxObjects;
        this.inputStream = inputStream;
    }


    public T safelyReadObject() throws IOException, ClassNotFoundException {

        // create an input stream limited to a certain number of bytes
        InputStream lis = new SecureFilterInputStream(inputStream);

        // create an object input stream that checks classes and limits the number of objects to read
        ObjectInputStream ois = new SecureObjectInputStream(lis);

        // use the protected ObjectInputStream to read object safely and cast to T
        return (T) ois.readObject();

    }

    /**
     * Filter Input stream override to enforce some security rules.
     */
    private class SecureFilterInputStream extends FilterInputStream {

        protected SecureFilterInputStream(InputStream in) {
            super(in);
        }

        @Override
        public int read() throws IOException {
            int val = super.read();
            if (val != -1) {
                length++;
                checkLength();
            }
            return val;
        }

        @Override
        public int read(byte[] bytes, int off, int len) throws IOException {
            int val = super.read(bytes, off, len);
            if (val > 0) {
                length += val;
                checkLength();
            }
            return val;
        }

        private void checkLength() throws IOException {
            if (length > maxBytes) {
                throw new SecurityException("Security violation: attempt to deserialize too many bytes"
                        + " from stream. Limit is " + maxBytes);
            }
        }

    }

    /**
     * Object Input stream override to enforce some security rules.
     */
    private class SecureObjectInputStream extends ObjectInputStream {

        private int objCount = 0;

        boolean status = enableResolveObject(true);

        protected SecureObjectInputStream(InputStream filteredInputStream) throws IOException {
            super(filteredInputStream);
        }

        @Override
        protected Object resolveObject(Object obj) throws IOException {
            if (objCount++ > maxObjects) {
                throw new SecurityException("Security violation: attempt to deserialize too many objects"
                        + " from stream. Limit is " + maxObjects);
            }
            return super.resolveObject(obj);
        }

        @Override
        protected Class<?> resolveClass(ObjectStreamClass osc) throws IOException, ClassNotFoundException {
            Class<?> clazz = super.resolveClass(osc);
            if (clazz.isArray() || clazz.equals(String.class)
                    || Number.class.isAssignableFrom(clazz) || safeClasses.contains(clazz)) {
                return clazz;
            }
            throw new SecurityException("Security violation: attempt to deserialize unauthorized " + clazz);
        }
    }

}
