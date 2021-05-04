extern crate cpython;

use cpython::{PyResult, Python, py_module_initializer, py_fn, PyObject, py_class};

use concrete::crypto_api::{LWEParams, LWE128_1024, LWE128_750, RLWE128_1024_1, RLWE128_2048_1};
mod zqz;
use zqz::keys::EncryptKey;
use zqz::max::max;

// We determine the cryptographic parameters depending on the compilation flag used.
#[cfg(not(any(feature = "z8z-ks", feature = "z16z-ks")))]
const PARAMS: zqz::Parameters =
    new_parameters!(3, 2, 6, 4, 1, 1, RLWE128_1024_1, LWE128_1024, false);
#[cfg(feature = "z16z-ks")]
const PARAMS: zqz::Parameters = new_parameters!(4, 2, 7, 3, 2, 7, RLWE128_2048_1, LWE128_750, true);
#[cfg(feature = "z8z-ks")]
// We define the cryptographic parameters of the demo
const PARAMS: zqz::Parameters = new_parameters!(3, 2, 7, 3, 2, 7, RLWE128_1024_1, LWE128_750, true);


py_module_initializer!(pyz8z, |py, m| {
    m.add(py, "__doc__", "This module is implemented in Rust.")?;
    m.add(py, "get_result", py_fn!(py, get_result(val: &str)))?;
    m.add(py, "setn", py_fn!(py, setn(val: u32)))?;
    m.add(py, "getn", py_fn!(py, getn()))?;
    m.add(py, "loadkeys", py_fn!(py, loadkeys()))?;
    m.add_class::<Z8EncryptKey>(py);
    m.add_class::<Z8Ciphertext>(py);
    Ok(())
});

fn get_result(_py: Python, val: &str) -> PyResult<String> {
    Ok("Rust says: ".to_owned() + val)
}

static mut N: u32 = 5;
//

unsafe fn setn(_py: Python, val: u32) -> PyResult<PyObject> {
    N = val;
    Ok(_py.None())
}

unsafe fn getn(_py: Python) -> PyResult<u32> {
    Ok(N*N)
}

static mut sk: Option<EncryptKey> = None;

unsafe fn loadkeys(_py: Python) -> PyResult<PyObject> {
    sk = Some(if !EncryptKey::keys_exist(&PARAMS.gen_prefix()) {
            let key = EncryptKey::new();
            key.save_to_files(&PARAMS.gen_prefix());
            key
        } else {
            EncryptKey::load_from_files(&PARAMS.gen_prefix())
    });
    Ok(_py.None())
}

py_class!(class Z8EncryptKey |py| {
    data key: EncryptKey;
    def __new__(_cls) -> PyResult<Z8EncryptKey> {
        Z8EncryptKey::create_instance(py, if !EncryptKey::keys_exist(&PARAMS.gen_prefix()) {
            let key = EncryptKey::new();
            key.save_to_files(&PARAMS.gen_prefix());
            key
        } else {
            EncryptKey::load_from_files(&PARAMS.gen_prefix())
        })
        //unsafe { match &sk {
        //    Some(ssk) => MyType::create_instance(py, ssk.encrypt(arg))
        //    //None     => MyType::create_instance()
        //} }
    }
    //def a(&self) -> PyResult<(PyObject)> {
    //    //println!("a() was called with self={:?}", self.data(py));
    //    Ok(py.None())
    //}
});

py_class!(class Z8Ciphertext |py| {
    data ciph: zqz::ciphertext::Ciphertext;
    def __new__(_cls, key: &Z8EncryptKey, val: usize) -> PyResult<Z8Ciphertext> {
        Z8Ciphertext::create_instance(py, key.key(py).encrypt(val))
    }
    
    def decrypt(&self, key: &Z8EncryptKey) -> PyResult<usize> {
        Ok(key.key(py).decrypt(&self.ciph(py)))
    }
    
    def addi(&self, val: usize) -> PyResult<Z8Ciphertext> {
        Z8Ciphertext::create_instance(py, self.ciph(py)+val)
    }
    
    def addc(&self, other: &Z8Ciphertext) -> PyResult<Z8Ciphertext> {
        Z8Ciphertext::create_instance(py, self.ciph(py)+other.ciph(py))
    }
    
    def subi(&self, val: usize) -> PyResult<Z8Ciphertext> {
        Z8Ciphertext::create_instance(py, self.ciph(py)-val)
    }
    
    def subc(&self, other: &Z8Ciphertext) -> PyResult<Z8Ciphertext> {
        Z8Ciphertext::create_instance(py, self.ciph(py)-other.ciph(py))
    }

    def muli(&self, val: usize) -> PyResult<Z8Ciphertext> {
        Z8Ciphertext::create_instance(py, self.ciph(py)*val)
    }
    
    def mulc(&self, other: &Z8Ciphertext) -> PyResult<Z8Ciphertext> {
        Z8Ciphertext::create_instance(py, self.ciph(py)*other.ciph(py))
    }
});


