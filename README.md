# devcon-l2beat-workshop
devcon-l2beat-workshop

## 動かし方

- セットアップ

    `.env`ファイルを作成する。

    ```txt
    ETHEREUM_ETHERSCAN_API_KEY=""
    ETHEREUM_RPC_URL=""
    ```

- インストール

    ```
    yarn
    ```

- 初期コントラクトから見つけられたすべてのコントラクトの情報を取得する

    ```bash
    npx discovery discover ethereum zora
    ```

    そうすると、`.flat`ディレクトリや `discovered.json`が生成される。



### 参考文献
1. [ワークショップ資料](https://matradomski.com/workshop/devcon/)