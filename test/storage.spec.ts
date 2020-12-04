// @ts-ignore
import AsyncStorage from '@react-native-async-storage/async-storage/jest/async-storage-mock';
jest.mock('@react-native-async-storage/async-storage', () => AsyncStorage);

describe("StorageTest", function () {
    test("Storage", async () => {
        await AsyncStorage.setItem('key','test')
        const res = await AsyncStorage.getItem('key')
        console.log(res)
    });
});
