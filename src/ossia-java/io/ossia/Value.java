package io.ossia;
import com.sun.jna.Pointer;
import com.sun.jna.Memory;
import com.sun.jna.Native;
import com.sun.jna.ptr.ByReference;
import com.sun.jna.ptr.PointerByReference;
import java.lang.Object;
import java.lang.Class;

public class Value implements AutoCloseable
{
  Value(Pointer p)
  {
    impl = p;
  }

  public Value()
  {
    impl = Ossia.INSTANCE.ossia_value_create_impulse();
  }

  public Value(float v)
  {
    impl = Ossia.INSTANCE.ossia_value_create_float(v);
  }
  public Value(double v)
  {
    impl = Ossia.INSTANCE.ossia_value_create_float((float)v);
  }
  public Value(int v)
  {
    impl = Ossia.INSTANCE.ossia_value_create_int(v);
  }
  public Value(boolean v)
  {
    impl = Ossia.INSTANCE.ossia_value_create_bool(v ? 1 : 0);
  }
  public Value(byte v)
  {
    impl = Ossia.INSTANCE.ossia_value_create_char(v);
  }
  public Value(String v)
  {
    impl = Ossia.INSTANCE.ossia_value_create_string(v);
  }
  public Value(float v1, float v2)
  {
    impl = Ossia.INSTANCE.ossia_value_create_2f(v1, v2);
  }
  public Value(float v1, float v2, float v3)
  {
    impl = Ossia.INSTANCE.ossia_value_create_3f(v1, v2, v3);
  }
  public Value(float v1, float v2, float v3, float v4)
  {
    impl = Ossia.INSTANCE.ossia_value_create_4f(v1, v2, v3, v4);
  }
  public Value(Vec2F v)
  {
    impl = Ossia.INSTANCE.ossia_value_create_2f(v.x, v.y);
  }
  public Value(Vec3F v)
  {
    impl = Ossia.INSTANCE.ossia_value_create_3f(v.x, v.y, v.z);
  }
  public Value(Vec4F v)
  {
    impl = Ossia.INSTANCE.ossia_value_create_4f(v.x, v.y, v.z, v.w);
  }
  public Value(int[] l)
  {
    impl = Ossia.INSTANCE.ossia_value_create_in(l, new SizeT(l.length));
  }
  public Value(float[] l)
  {
    impl = Ossia.INSTANCE.ossia_value_create_fn(l, new SizeT(l.length));
  }
  public Value(Value[] l)
  {
    final int sz = Native.POINTER_SIZE;
    final Memory p = new Memory(l.length * sz);

    for (int i = 0; i < l.length; i++) {
      p.setPointer(i * sz, l[i].impl);
    }
    impl = Ossia.INSTANCE.ossia_value_create_list(p, new SizeT(l.length));
  }



  public void set_impulse()
  {
    close();
    impl = Ossia.INSTANCE.ossia_value_create_impulse();
  }
  public void set(float v)
  {
    close();
    impl = Ossia.INSTANCE.ossia_value_create_float(v);
  }
  public void set(int v)
  {
    close();
    impl = Ossia.INSTANCE.ossia_value_create_int(v);
  }
  public void set(boolean v)
  {
    close();
    impl = Ossia.INSTANCE.ossia_value_create_bool(v ? 1 : 0);
  }
  public void set(byte v)
  {
    close();
    impl = Ossia.INSTANCE.ossia_value_create_char(v);
  }
  public void set(String v)
  {
    close();
    impl = Ossia.INSTANCE.ossia_value_create_string(v);
  }
  public void set(float v1, float v2)
  {
    close();
    impl = Ossia.INSTANCE.ossia_value_create_2f(v1, v2);
  }
  public void set(float v1, float v2, float v3)
  {
    close();
    impl = Ossia.INSTANCE.ossia_value_create_3f(v1, v2, v3);
  }
  public void set(float v1, float v2, float v3, float v4)
  {
    close();
    impl = Ossia.INSTANCE.ossia_value_create_4f(v1, v2, v3, v4);
  }
  public void set(int[] l)
  {
    close();
    impl = Ossia.INSTANCE.ossia_value_create_in(l, new SizeT(l.length));
  }
  public void set(float[] l)
  {
    close();
    impl = Ossia.INSTANCE.ossia_value_create_fn(l, new SizeT(l.length));
  }
  public void set(Value[] l)
  {
    final int sz = Native.POINTER_SIZE;
    final Memory p = new Memory(l.length * sz);

    for (int i = 0; i < l.length; i++) {
      p.setPointer(i * sz, l[i].impl);
    }
    close();
    impl = Ossia.INSTANCE.ossia_value_create_list(p, new SizeT(l.length));
  }

  public float getFloat()
  {
    return Ossia.INSTANCE.ossia_value_to_float(impl);
  }
  public int getInt()
  {
    return Ossia.INSTANCE.ossia_value_to_int(impl);
  }
  public byte getChar()
  {
    return Ossia.INSTANCE.ossia_value_to_char(impl);
  }
  public String getString()
  {
    Pointer p = Ossia.INSTANCE.ossia_value_to_string(impl);
    String str = p.getString(0);
    Ossia.INSTANCE.ossia_string_free(p);
    return str;
  }
  public Vec2F getVec2()
  {
    return Ossia.INSTANCE.ossia_value_to_2f(impl);
  }
  public Vec3F getVec3()
  {
    return Ossia.INSTANCE.ossia_value_to_3f(impl);
  }
  public Vec4F getVec4()
  {
    return Ossia.INSTANCE.ossia_value_to_4f(impl);
  }
  public boolean getBoolean()
  {
    return Ossia.INSTANCE.ossia_value_to_bool(impl);
  }

  public float asFloat()
  {
    return Ossia.INSTANCE.ossia_value_convert_float(impl);
  }
  public int asInt()
  {
    return Ossia.INSTANCE.ossia_value_convert_int(impl);
  }
  public byte asChar()
  {
    return Ossia.INSTANCE.ossia_value_convert_char(impl);
  }
  public String asString()
  {
    Pointer p = Ossia.INSTANCE.ossia_value_to_string(impl);
    String str = p.getString(0);
    Ossia.INSTANCE.ossia_string_free(p);
    return str;
  }
  public Vec2F asVec2()
  {
    return Ossia.INSTANCE.ossia_value_convert_2f(impl);
  }
  public Vec3F asVec3()
  {
    return Ossia.INSTANCE.ossia_value_convert_3f(impl);
  }
  public Vec4F asVec4()
  {
    return Ossia.INSTANCE.ossia_value_convert_4f(impl);
  }
  public boolean asBoolean()
  {
    return Ossia.INSTANCE.ossia_value_convert_bool(impl);
  }
  public int[] asInts()
  {
    int[] list = new int[0];

    if(getType() != Type.LIST_T)
    {
      return list;
    }

    final PointerByReference ptr = new PointerByReference();
    final SizeTByReference sz = new SizeTByReference();

    Ossia.INSTANCE.ossia_value_to_in(impl, ptr, sz);

    int n = sz.getValue().intValue();
    list = new int[n];

    int type_sz = Native.getNativeSize(Integer.TYPE);

    if (n > 0) {
      final Pointer vals = ptr.getValue();

      for (int i = 0; i < n; i++) {
        list[i] = vals.getInt(i * type_sz);
      }

      Ossia.INSTANCE.ossia_value_free_fn(vals);
    }

    return list;
  }

  public float[] asFloats()
  {
    float[] list = new float[0];

    if(getType() != Type.LIST_T)
    {
      return list;
    }

    final PointerByReference ptr = new PointerByReference();
    final SizeTByReference sz = new SizeTByReference();

    Ossia.INSTANCE.ossia_value_to_fn(impl, ptr, sz);

    final int n = sz.getValue().intValue();
    list = new float[n];

    final int type_sz = Native.getNativeSize(Float.TYPE);

    if (n > 0) {
      final Pointer vals = ptr.getValue();

      for (int i = 0; i < n; i++) {
        list[i] = vals.getFloat(i * type_sz);
      }

      Ossia.INSTANCE.ossia_value_free_in(vals);
    }

    return list;
  }

  public Value[] asList()
  {
    Value[] list = new Value[0];

    if(getType() != Type.LIST_T)
    {
      return list;
    }

    final PointerByReference ptr = new PointerByReference();
    final SizeTByReference sz = new SizeTByReference();

    Ossia.INSTANCE.ossia_value_to_list(impl, ptr, sz);

    final int n = sz.getValue().intValue();
    list = new Value[n];

    final int type_sz = Native.POINTER_SIZE;

    if (n > 0) {
      final Pointer vals = ptr.getValue();

      for (int i = 0; i < n; i++) {
        list[i] = new Value(vals.getPointer(i * type_sz));
      }

      Ossia.INSTANCE.ossia_value_free_list(vals);
    }

    return list;
  }

  public int getType()
  {
    return Ossia.INSTANCE.ossia_value_get_type(impl);
  }

  public boolean isImpulse()
  {
    return getType() == Type.IMPULSE_T;
  }
  public boolean isFloat()
  {
    return getType() == Type.FLOAT_T;
  }
  public boolean isInt()
  {
    return getType() == Type.INT_T;
  }
  public boolean isChar()
  {
    return getType() == Type.CHAR_T;
  }
  public boolean isVec2()
  {
    return getType() == Type.VEC2F_T;
  }
  public boolean isVec3()
  {
    return getType() == Type.VEC3F_T;
  }
  public boolean isVec4()
  {
    return getType() == Type.VEC4F_T;
  }
  public boolean isBoolean()
  {
    return getType() == Type.BOOL_T;
  }
  public boolean isList()
  {
    return getType() == Type.LIST_T;
  }


  @Override
  public void close()
  {
    Ossia.INSTANCE.ossia_value_free(impl);
  }

  Pointer impl;
}
