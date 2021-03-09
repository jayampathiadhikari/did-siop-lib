//if window.localStorage undefined use react native as storage
export class Storage {
    private storage: any;
    constructor(){
        if(typeof window != "undefined"){
            this.storage = window.localStorage;
        }
    }

    setStorage = (storage:any) => {
        this.storage = storage
    };

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
