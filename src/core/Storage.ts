import AsyncStorage from '@react-native-async-storage/async-storage';

class Storage {
    private storage = AsyncStorage;

    setItem = async (key:string, value:string, expiresIn:number = 1000*60*10) => {
        try{
            await this.storage.setItem(key,value);
            setTimeout(() => {this.storage.removeItem(key)}, expiresIn);
            return true;
        }catch (e) {
            throw (e)
        }
    };

    getItem = async(key:string) => {
        try{
            const item = await this.storage.getItem(key);
            return item;
        }catch (e) {
            throw (e)
        }
    };

};

export default new Storage();
