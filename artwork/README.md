# LayerAnalyzer 图标

深墨绿底色与三层薄荷青叠片，呼应应用的协议分层分析和现有界面。顶层的数据链路代表数据包的连接与流动；图标不含文字，小尺寸也能辨认。

- `launcher-icon.svg`：可缩放的完整方形图稿。
- `launcher-icon.png`：512 × 512 PNG 图稿，无预置圆角。
- `launcher-icon-preview.png`：圆形、圆角、超椭圆、单色主题及小尺寸效果预览。具体裁切和主题配色由启动器决定。

Android 实际使用 `app/src/main/res/drawable/ic_launcher_*.xml` 矢量资源。前景采用 108 × 108 坐标，主体位于中央直径 66 的安全区内，背景延伸至整个画布。Android 8–12 使用彩色自适应图标；Android 13 及以上另提供单色主题图层，数据链路在单色版本中简化为镂空折线。

修改 Android 矢量后，在安装了 `resvg-py==0.5.0` 的 Python 环境中运行以下命令，同步导出图稿及预览；应用构建不依赖此工具。

```sh
python tools/export_launcher_icon.py
```
